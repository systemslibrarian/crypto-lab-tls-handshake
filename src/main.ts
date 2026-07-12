import './style.css';
import { runFullHandshake, runMitmAttempt, type HandshakeTrace, type HandshakeStep, type MitmResult } from './handshake';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app root');
}
const appRoot = app;

interface State {
  trace: HandshakeTrace;
  step: number; // 0..steps.length-1
  mitm: MitmResult | null;
  autoPlay: boolean;
  autoTimer: number | null;
}

const state: State = {
  trace: await runFullHandshake(),
  step: 0,
  mitm: null,
  autoPlay: false,
  autoTimer: null,
};

// ---- small helpers ---------------------------------------------------------

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] ?? c);
}

function pill(ok: boolean, label: string, alarmOnFail = false): string {
  const cls = ok ? 'good' : alarmOnFail ? 'alarm' : 'bad';
  const icon = ok ? '✓' : '✗';
  return `<span class="pill ${cls}">${icon} ${esc(label)}</span>`;
}

function lockBadge(kind: HandshakeStep['encrypted']): string {
  const text = kind === 'plaintext' ? '🔓 cleartext' : kind === 'handshake' ? '🔒 handshake key' : '🔒 app key';
  return `<span class="lock ${kind}">${text}</span>`;
}

function stopAuto(): void {
  if (state.autoTimer !== null) {
    window.clearInterval(state.autoTimer);
    state.autoTimer = null;
  }
  state.autoPlay = false;
}

// ---- section renderers -----------------------------------------------------

function overviewSection(): string {
  return `
  <section class="panel">
    <h2><span class="section-num">1</span> What TLS 1.3 Gives You</h2>
    <p class="lead">TLS is the protocol behind every <code>https://</code> connection. The handshake's job is to turn an
      open, untrusted network into a channel with three properties — using cryptographic primitives you may have only
      met in isolation. TLS 1.3 (RFC 8446) is a major cleanup of TLS 1.2: fewer round trips, forward secrecy by
      default, and all the legacy/insecure options removed.</p>
    <div class="pillars">
      <div class="pillar"><strong>Confidentiality</strong><span>Eavesdroppers see only ciphertext. Provided by AEAD (AES-128-GCM here).</span></div>
      <div class="pillar"><strong>Integrity</strong><span>Tampering is detected and rejected. Provided by the AEAD tag and Finished MACs.</span></div>
      <div class="pillar"><strong>Authentication</strong><span>You're talking to the real server, not a MITM. Provided by certificates + signatures.</span></div>
    </div>
    <div class="flow-chips" aria-label="High level message flow">
      <span>ClientHello</span><span class="arrow">→</span>
      <span>ServerHello</span><span class="arrow">→</span>
      <span>Certificate</span><span class="arrow">→</span>
      <span>CertificateVerify</span><span class="arrow">→</span>
      <span>Finished</span><span class="arrow">→</span>
      <span>Application Data</span>
    </div>
  </section>`;
}

function ladderRow(s: HandshakeStep, idx: number): string {
  const dirClass = s.to === 'server' ? 'to-server' : 'to-client';
  const stateClass = idx === state.step ? 'current' : idx < state.step ? 'seen' : '';
  const wire = s.to === 'server' ? '──▶' : '◀──';
  return `
    <button class="msg ${dirClass} ${stateClass}" data-step="${idx}" aria-current="${idx === state.step ? 'step' : 'false'}"
      aria-label="Step ${idx + 1}: ${esc(s.title)}, ${s.from} to ${s.to}">
      <span class="label">${esc(s.title)}<br><span class="bytes">${s.bytesOnWire} B · ${lockBadge(s.encrypted)}</span></span>
      <span class="wire">${wire}</span>
      <span class="label"></span>
    </button>`;
}

function detailCard(s: HandshakeStep): string {
  const keys = s.derived.length
    ? `<h4>Keys &amp; secrets derived</h4><div class="keys">${s.derived
        .map((k) => `<div class="keyrow"><span class="kname">${esc(k.name)} (${k.bytes} B)</span><span class="kval">${esc(k.preview)}</span></div>`)
        .join('')}</div>`
    : '';
  return `
    <div class="detail" aria-live="polite" aria-atomic="true">
      <h3>${esc(s.title)} ${lockBadge(s.encrypted)}</h3>
      <p class="dir">Flight ${s.flight} · ${s.from.toUpperCase()} → ${s.to.toUpperCase()} · ${s.bytesOnWire} bytes on the wire</p>
      <h4>What happens cryptographically</h4>
      <ul>${s.cryptoOps.map((o) => `<li>${esc(o)}</li>`).join('')}</ul>
      ${keys}
      <h4>Security properties so far</h4>
      <ul>${s.security.map((o) => `<li>${esc(o)}</li>`).join('')}</ul>
    </div>`;
}

function simulatorSection(t: HandshakeTrace): string {
  const s = t.steps[state.step];
  return `
  <section class="panel">
    <h2><span class="section-num">2</span> Interactive Handshake Simulator</h2>
    <p class="lead">Step through a complete 1-RTT handshake to <code>${esc(t.serverName)}</code>. Each message is real:
      the keys shown are derived from this session's X25519 secret and message transcript. Click a message, use the
      Step controls, or press ← / → .</p>
    <div class="controls">
      <button class="btn" id="prevBtn" aria-label="Previous step">◀ Back</button>
      <button class="btn primary" id="nextBtn" aria-label="Next step">Step ▶</button>
      <button class="btn" id="autoBtn" aria-pressed="${state.autoPlay}" aria-label="Toggle auto play">${state.autoPlay ? '⏸ Stop' : '▶ Auto-play'}</button>
      <button class="btn" id="resetBtn" aria-label="Start a new session with fresh keys">↻ New session</button>
      <span class="progress">Step ${state.step + 1} / ${t.steps.length}</span>
    </div>
    <div class="sim" style="margin-top:1rem">
      <div class="ladder">
        <div class="lane-heads"><span class="c">CLIENT</span><span class="s">SERVER</span></div>
        ${t.steps.map((step, i) => ladderRow(step, i)).join('')}
      </div>
      ${detailCard(s)}
    </div>
  </section>`;
}

function keyExchangeSection(t: HandshakeTrace): string {
  const she = t.steps.find((s) => s.id === 'server-hello');
  const ecdhe = she?.derived.find((d) => d.name.includes('ECDHE'))?.preview ?? '';
  const clientPub = t.steps[0].derived[0]?.preview ?? '';
  return `
  <section class="panel">
    <h2><span class="section-num">3</span> Key Exchange — X25519 (EC)DHE</h2>
    <p class="lead">Client and server each send an <em>ephemeral</em> X25519 public key. Each combines its own private
      key with the peer's public key and arrives at the identical shared secret — without that secret ever crossing the
      wire. This is Diffie–Hellman over Curve25519.</p>
    <div class="two">
      <div class="card client">
        <div class="role" style="color:var(--client)">CLIENT key_share</div>
        <p class="mono">X25519 pub: <span class="hl">${esc(clientPub)}</span></p>
      </div>
      <div class="card server">
        <div class="role" style="color:var(--server)">SERVER key_share</div>
        <p class="mono">ECDHE shared: <span class="hl">${esc(ecdhe)}</span></p>
      </div>
    </div>
    <p class="lead" style="margin-top:0.8rem">${pill(t.sharedSecretAgrees, 'both sides computed the same 32-byte ECDHE secret')}</p>
    <p class="lead">Modern deployments wrap this in a <strong>hybrid</strong> exchange (X25519 + ML-KEM-768) so the
      session survives a future quantum computer. See
      <a href="https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/">pq-tls-handshake</a> and
      <a href="https://systemslibrarian.github.io/crypto-lab-key-exchange/">key-exchange</a>.</p>
  </section>`;
}

function authSection(t: HandshakeTrace): string {
  const v = t.chainVerdict;
  const mitm = state.mitm;
  const mitmHtml = mitm
    ? `<div class="mitm-box ${mitm.attackBlocked ? 'blocked' : ''}">
         <strong>${mitm.attackBlocked ? '🛡 MITM blocked' : '⚠ MITM SUCCEEDED'}</strong>
         <div class="verdicts">
           ${pill(mitm.keyExchangeSucceeded, 'attacker completed ECDHE')}
           ${pill(mitm.presentedRealCertificate, 'replayed a valid certificate')}
           ${pill(!mitm.certificateVerifyAccepted, 'forged CertificateVerify rejected', true)}
         </div>
         <ol>${mitm.explanation.map((e) => `<li>${esc(e)}</li>`).join('')}</ol>
       </div>`
    : `<button class="btn" id="mitmBtn" style="margin-top:0.9rem" aria-label="Simulate a man in the middle attack">▶ Simulate a MITM attack</button>`;

  return `
  <section class="panel">
    <h2><span class="section-num">4</span> Authentication — Certificates &amp; Signatures</h2>
    <p class="lead">Key exchange alone proves nothing about <em>who</em> is on the other end — an attacker can do ECDHE
      too. The server proves its identity with a certificate chain plus a <code>CertificateVerify</code> signature over
      the live transcript, using a private key only the real server holds.</p>
    <div class="chain">
      <div class="cert"><div class="role">TRUST ANCHOR · ROOT CA</div><div class="subject">${esc(t.chain.root.subject)}</div>
        <div class="mono">Ed25519 pub: <span class="hl">${esc(shortHex(t.chain.root.publicKey))}</span> · self-signed</div></div>
      <div class="chain-link">▲ signs</div>
      <div class="cert"><div class="role">LEAF · SERVER CERT</div><div class="subject">${esc(t.chain.leaf.subject)}</div>
        <div class="mono">Ed25519 pub: <span class="hl">${esc(shortHex(t.chain.leaf.publicKey))}</span> · issued by ${esc(t.chain.leaf.issuer)}</div></div>
    </div>
    <div class="verdicts">
      ${pill(v.trustAnchorMatches, 'root matches trust anchor')}
      ${pill(v.rootSelfSignatureValid, 'root self-signature valid')}
      ${pill(v.leafSignatureValid, 'leaf signed by root')}
      ${pill(t.certificateVerifyValid, 'CertificateVerify signature valid')}
    </div>
    <p class="lead" style="margin-top:0.7rem">Each check is reported independently, so a failure points at the exact
      broken link. Now watch what happens when an attacker tries to impersonate the server:</p>
    ${mitmHtml}
  </section>`;
}

function scheduleSection(t: HandshakeTrace): string {
  const k = t.schedule;
  const row = (tag: string, name: string, bytes: Uint8Array | undefined, indent = false): string => {
    const val = bytes ? shortHex(bytes) : '';
    return `<div class="kstage ${indent ? 'indent' : ''}"><span class="tag">${esc(tag)}</span><span class="name">${esc(name)}</span><span class="val">${esc(val)}</span></div>`;
  };
  return `
  <section class="panel">
    <h2><span class="section-num">5</span> Key Derivation &amp; Forward Secrecy</h2>
    <p class="lead">One ECDHE secret is never used directly. The TLS 1.3 key schedule (RFC 8446 §7.1) runs it through
      HKDF to derive a tree of independent secrets — one per direction, per phase — so compromising one never exposes
      the others. Every value below is the real HKDF output for this session.</p>
    <div class="schedule">
      ${row('Extract', 'Early Secret', k.earlySecret)}
      ${row('Extract', 'Handshake Secret  (← ECDHE)', k.handshakeSecret)}
      ${row('Derive', 'client handshake traffic', k.clientHandshakeTrafficSecret, true)}
      ${row('Derive', 'server handshake traffic', k.serverHandshakeTrafficSecret, true)}
      ${row('Extract', 'Master Secret', k.masterSecret)}
      ${row('Derive', 'client application traffic', k.clientApplicationTrafficSecret, true)}
      ${row('Derive', 'server application traffic', k.serverApplicationTrafficSecret, true)}
      ${row('Derive', 'exporter master', k.exporterMasterSecret, true)}
    </div>
    <p class="lead" style="margin-top:0.8rem"><strong>Forward secrecy:</strong> the X25519 private keys are ephemeral —
      generated for this session and discarded the moment it ends. An attacker who later steals the server's long-term
      certificate key still cannot recover these session keys, so recorded traffic stays secret. Contrast with old
      RSA key-transport (TLS ≤1.2), where the long-term key decrypts every past session it ever protected.</p>
  </section>`;
}

function recordSection(t: HandshakeTrace): string {
  const r = t.record;
  return `
  <section class="panel">
    <h2><span class="section-num">6</span> Record Layer — AEAD (AES-128-GCM)</h2>
    <p class="lead">After the handshake, application data is protected by authenticated encryption. The record key and IV
      are HKDF-derived from the application traffic secret; each record uses a fresh nonce
      (<code>write_iv XOR sequence_number</code>) so a key never reuses a GCM nonce. Below is a real first request,
      sealed with this session's client key.</p>
    <div class="record-grid">
      <div class="field"><label>Plaintext (record 0)</label><div class="codebox">${esc(r.plaintext)}</div></div>
      <div class="field"><label>Per-record nonce (write_iv ⊕ seq 0)</label><div class="codebox">${esc(r.nonceHex)}</div></div>
      <div class="field"><label>AAD — record header (type ‖ version ‖ length)</label><div class="codebox">${esc(r.aadHex)}</div></div>
      <div class="field"><label>Ciphertext + GCM tag (${r.ciphertextBytes} B)</label><div class="codebox ct">${esc(r.ciphertextHex)}</div></div>
    </div>
    <div class="verdicts" style="margin-top:0.7rem">
      ${pill(r.roundTripOk, 'decrypts back to the exact plaintext')}
      ${pill(r.tamperRejected, 'one flipped byte → GCM rejects it', true)}
    </div>
  </section>`;
}

function comparisonSection(): string {
  return `
  <section class="panel">
    <h2><span class="section-num">7</span> TLS 1.3 vs 1.2 &amp; Takeaways</h2>
    <table>
      <caption class="lead">How TLS 1.3 cleaned up the handshake</caption>
      <thead><tr><th>Property</th><th>TLS 1.2</th><th>TLS 1.3</th></tr></thead>
      <tbody>
        <tr><td>Handshake round trips</td><td class="no">2-RTT</td><td class="yes">1-RTT (0-RTT optional)</td></tr>
        <tr><td>Forward secrecy</td><td class="no">Optional (often RSA key transport)</td><td class="yes">Mandatory (ephemeral (EC)DHE)</td></tr>
        <tr><td>Cipher negotiation</td><td class="no">Huge legacy menu (RC4, CBC, export)</td><td class="yes">5 AEAD suites, no legacy</td></tr>
        <tr><td>Handshake encryption</td><td class="no">Mostly in the clear</td><td class="yes">Encrypted after ServerHello</td></tr>
        <tr><td>Key derivation</td><td class="no">Custom PRF</td><td class="yes">HKDF, clearly specified schedule</td></tr>
      </tbody>
    </table>
    <ul class="takeaways">
      <li><strong>Key exchange ≠ authentication.</strong> ECDHE gives you a shared secret with <em>someone</em>; signatures prove it's the right someone.</li>
      <li><strong>Forward secrecy is structural,</strong> not a setting — it comes from throwing away ephemeral keys.</li>
      <li><strong>Common real-world failures:</strong> trusting an unvalidated certificate, accepting downgrades to TLS 1.2/1.0, expired or misissued certs, and missing SNI/hostname checks.</li>
    </ul>
  </section>`;
}

function shortHex(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return hex.length <= 24 ? hex : `${hex.slice(0, 12)}…${hex.slice(-12)}`;
}

function footer(): string {
  return `
  <footer class="scripture-footer">
    <div class="related"><strong>Related demos:</strong>
      <a href="https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/">pq-tls-handshake</a> ·
      <a href="https://systemslibrarian.github.io/crypto-lab-ssh-handshake/">ssh-handshake</a> ·
      <a href="https://systemslibrarian.github.io/crypto-lab-key-exchange/">key-exchange</a> ·
      <a href="https://systemslibrarian.github.io/crypto-lab-pki-chain/">pki-chain</a> ·
      <a href="https://systemslibrarian.github.io/crypto-lab-noise-pipe/">noise-pipe</a>
    </div>
    <div><a href="https://github.com/systemslibrarian/crypto-lab-tls-handshake">Source on GitHub</a> ·
      <a href="https://crypto-lab.systemslibrarian.dev/">More crypto-lab demos</a></div>
    <p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p>
  </footer>`;
}

// ---- render + wiring -------------------------------------------------------

function render(): void {
  const t = state.trace;
  appRoot.innerHTML = `
    <main class="shell" aria-label="TLS 1.3 handshake walkthrough">
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">TLS 1.3 Handshake</h1>
          <p class="cl-hero-sub">TLS 1.3 · RFC 8446</p>
          <p class="cl-hero-desc">Step through a real 1-RTT handshake and watch ephemeral X25519 key exchange, Ed25519
            certificate authentication, the HKDF key schedule, and AES-128-GCM record protection combine live in your
            browser — with an MITM attempt you can run yourself.</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">HTTPS guards every login, payment, and message you send. Key exchange alone gives
            you a shared secret with <em>someone</em>; only the certificate signature proves it's the real server, and
            that authentication step is exactly what stops a machine-in-the-middle from silently reading it all.</p>
        </aside>
      </header>
      ${overviewSection()}
      ${simulatorSection(t)}
      ${keyExchangeSection(t)}
      ${authSection(t)}
      ${scheduleSection(t)}
      ${recordSection(t)}
      ${comparisonSection()}
    </main>
    ${footer()}`;

  wire();
}

function go(step: number): void {
  state.step = Math.max(0, Math.min(state.trace.steps.length - 1, step));
  render();
}

function wire(): void {
  document.querySelector('#nextBtn')?.addEventListener('click', () => {
    stopAuto();
    go(state.step + 1);
  });
  document.querySelector('#prevBtn')?.addEventListener('click', () => {
    stopAuto();
    go(state.step - 1);
  });
  document.querySelector('#resetBtn')?.addEventListener('click', async () => {
    stopAuto();
    state.trace = await runFullHandshake();
    state.mitm = null;
    state.step = 0;
    render();
  });
  document.querySelector('#autoBtn')?.addEventListener('click', () => {
    if (state.autoPlay) {
      stopAuto();
      render();
      return;
    }
    if (state.step >= state.trace.steps.length - 1) {
      state.step = 0;
    }
    state.autoPlay = true;
    state.autoTimer = window.setInterval(() => {
      if (state.step >= state.trace.steps.length - 1) {
        stopAuto();
        render();
        return;
      }
      state.step += 1;
      render();
    }, 1500);
    render();
  });
  document.querySelector('#mitmBtn')?.addEventListener('click', async () => {
    state.mitm = await runMitmAttempt(state.trace.serverName);
    render();
  });
  document.querySelectorAll<HTMLButtonElement>('.msg[data-step]').forEach((btn) => {
    btn.addEventListener('click', () => {
      stopAuto();
      go(Number(btn.dataset.step));
    });
  });
}

// Global keyboard navigation for the simulator.
window.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowRight') {
    stopAuto();
    go(state.step + 1);
  } else if (e.key === 'ArrowLeft') {
    stopAuto();
    go(state.step - 1);
  }
});

render();
