# crypto-lab-tls-handshake

> **TLS 1.3 Handshake** — an interactive, step-by-step walkthrough of how a modern
> HTTPS connection is established. Real WebCrypto + real primitives, no backend.

## What It Is

A browser demo of a complete **TLS 1.3** (RFC 9846) full handshake and PSK resumption,
run entirely in the page with no server. It uses genuine cryptographic primitives — **X25519** ephemeral
key exchange, **Ed25519** certificate-chain and `CertificateVerify` signatures, the
**HKDF** key schedule (`HKDF-Extract` / `HKDF-Expand-Label` / `Derive-Secret`), HMAC
`Finished` MACs, and **AES-128-GCM** record protection. It surfaces the running
**transcript hash** as a first-class value so you can see exactly what each signature and
MAC is bound to. The extension derives a ticket PSK, computes and verifies the truncated-
ClientHello binder, compares `psk_dhe_ke` with the deliberately weak `psk_ke`, protects real
0-RTT records, and lets you replay a bill payment against five server policies. It is an honest
educational simulation, not a hardened TLS stack: it deliberately omits HelloRetryRequest,
client authentication, X.509 encoding, and every name/validity/revocation check a real client
performs. The page states those boundaries itself, in a Scope panel.

## Exhibits

1. **What TLS 1.3 Gives You** — confidentiality, integrity, authentication, and the message flow.
2. **Interactive Handshake Simulator** — the eight-message 1-RTT trace and break-it-yourself faults.
3. **Key Exchange** — both X25519 computations shown byte for byte.
4. **Authentication** — the model chain, `CertificateVerify`, and three live MITM strategies.
5. **Key Derivation & Forward Secrecy** — the no-PSK full-handshake schedule and one worked HKDF expansion.
6. **Record Layer** — an AES-128-GCM application record and tamper rejection.
7. **Resumption & 0-RTT** — ticket-to-PSK derivation, binder failure, STEK compromise, and replay policies.
8. **TLS 1.3 vs 1.2 & Takeaways** — the protocol cleanup in context.
9. **Scope** — what is faithful, compressed, or deliberately absent.

## What Can Go Wrong

- **0-RTT is replayable.** A valid ticket and binder authenticate the recorded first flight; they do not prove freshness. The broken policy executes the modelled bill payment twice.
- **`psk_ke` has no fresh (EC)DHE input.** Leaking the STEK later recovers the ticket PSK and opens recorded resumed 1-RTT data. The default `psk_dhe_ke` keeps that 1-RTT data sealed, though its PSK-derived 0-RTT data is still exposed.
- **A local replay cache is local.** ClientHello recording refuses a duplicate in region A while region B, sharing the STEK but not the recording store, accepts it.
- **Every ticket-based early-data policy checks ticket age.** Single-use tickets and ClientHello recording add duplicate tracking. Freshness alone rejects late copies but permits replays inside the tolerance.
- **Failed full handshakes cannot establish resumption.** A failed chain, signature, Finished check, or shared-secret agreement prevents ticket issuance and retires the resumption panel's previous results.
- **Ticket authentication precedes binder verification.** Flipping opaque ticket bytes fails ticket AEAD; flipping only the binder fails the binder check. Neither failure releases early plaintext.

## When to Use It

- **Teaching how a real handshake fits together** — students who learned Diffie–Hellman, signatures, and AEAD in isolation can see them combine into one protocol.
- **Showing why authentication, not key exchange, stops a MITM** — the attack panel runs three different attacker strategies against the *current session's* real chain and real transcript, and shows which check each one trips: reusing the server's certificate fails the signature, signing with the attacker's own key fails the trust anchor, and relaying unchanged passes every check while gaining the attacker nothing.
- **Explaining forward secrecy concretely** — the server's Ed25519 certificate key persists across sessions while the X25519 keys are generated per session and discarded, so you can press *New session* and watch the long-term key stay put while every derived secret changes.
- **Walking the TLS 1.3 key schedule** — every secret in the RFC 9846 §7.1 tree is shown as the real HKDF output for the current session.
- **Demonstrating the latency/security tradeoff in resumption** — record and replay the exact ClientHello + early-data bytes, then compare five computed admission policies.
- **Do NOT use it as a TLS library.** It is an educational tool; JavaScript here is not constant-time and the chain validation is intentionally minimal. For production, use a vetted TLS implementation.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-tls-handshake](https://systemslibrarian.github.io/crypto-lab-tls-handshake/)**

Step through the eight steps — the seven handshake messages plus the first application
record — one flight at a time (Step / Back / Auto-play, arrow keys, or click any message);
a labelled packet flies along the wire, tinted by its encryption layer (cleartext /
handshake-key / app-key). Each step shows what cryptographic
operation runs, which keys are derived, and — as a **live transcript-hash chip** — the
exact SHA-256 that `CertificateVerify` signs and the `Finished` MACs cover, so transcript
binding is a value you watch change rather than a claim. The chip names the run it is a
hash of (`SHA-256(ClientHello..Certificate)`) rather than the step's ordinal, because a
signature or MAC necessarily covers the transcript ending just *before* its own message.
A **Break this handshake** panel under the ladder re-runs the whole real handshake with a
fault you choose and reports the four verifier booleans it produced — *break the ECDHE
agreement* (one bit of the client's X25519 output flipped) or *flip a byte in flight* (one
byte of `EncryptedExtensions` altered between server and client). The separation is the
lesson: under the ECDHE fault the chain and `CertificateVerify` still verify — authentication
proves *who* the peer is, not that you share keys with them — and both `Finished` MACs are
what catch it; under the in-flight byte flip the client hashes what it received, so the
server's real signature no longer fits the client's transcript and every transcript-bound
check fails at once. Each verdict is the return value of the same `verifyFinished` /
`verifyCertificateVerify` calls the honest run makes. The **key-exchange panel** shows
both sides fully: each combines its own (masked) private key with the peer's public key,
and the two independently-computed 32-byte secrets are stacked with a **byte-level match
highlight** — different private inputs, byte-identical output, the Diffie–Hellman "aha".
The authentication panel validates the certificate chain and lets you choose the
attacker's move in a **MITM panel** — *reuse the server's certificate*, *sign with its own
key*, or *relay unchanged*. Each runs against this session's own ClientHello, chain, and
`CertificateVerify` signature, so the "genuine session" transcript it compares against is
literally the value the Certificate step shows above; every verdict is the output of the
same chain and signature verification the honest handshake runs, and the panel reports
separately whether the client accepted and whether the attacker ended up holding the
session secret. The key-schedule panel renders
the live HKDF tree plus an expandable **"show one derivation in full"** view — inputs →
`HKDF-Expand-Label(secret, label, context)` → output, with byte-length bars. The
record-layer panel encrypts a real HTTP request with AES-128-GCM and proves tampering is
rejected. Inline dotted-underline definitions cover ECDHE, AEAD, AAD, IV/nonce, and the
transcript hash. Press **New session** for fresh ephemeral keys — the server's long-term
leaf key stays the same. A **Resumption &amp; 0-RTT** panel then issues an RFC-shaped
NewSessionTicket, derives the PSK and binder, toggles both PSK establishment modes, and runs a
recorded-wire STEK compromise. The resumption ClientHello advertises X25519 in `supported_groups`
and Ed25519 for certificate fallback, with `pre_shared_key` last. Its replay console processes the
original only in region A, then one replay in each region; each region displays its own admission
log and payment count. Certificate handshakes and `psk_dhe_ke` provide forward secrecy through
fresh (EC)DHE; `psk_ke` and 0-RTT do not. A closing **Scope** panel states
in the page itself what is
modelled faithfully and what is not: the certificate chain is not X.509 (so the
`Certificate` step's byte count is this demo's encoding), no hostname/SAN, validity, or
revocation check exists, HelloRetryRequest and client authentication are omitted, nothing is negotiated,
and only application-data records (including 0-RTT) are actually AEAD-sealed.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-tls-handshake
cd crypto-lab-tls-handshake
npm install
npm run dev
```

Verification:

```bash
npm run typecheck   # tsc strict, no emit
npm test            # RFC 8448 full/resumed vectors + schedules, auth/MITM, AEAD, replay gates
npm run build       # type-check + production bundle
npm run test:a11y   # claims + WCAG A/AA drive, including the new panel at 320px
npm run test:mutations # 14 replayable behavioural mutations; requires a clean committed tree
```

`npm test` runs `scripts/phase-checks.ts`: the RFC 8448 `HKDF-Expand-Label`/Early-Secret
vectors, a deterministic distinct-secrets key-schedule check, certificate-chain
accept/reject and `CertificateVerify` forge-rejection, a long-term-identity check (the leaf
key survives a new session, the session secrets do not), per-strategy MITM invariants —
including that each strategy is run against the session's own CertificateVerify transcript
— AES-128-GCM round-trip + tamper rejection + per-record nonce uniqueness, a 40-session
end-to-end agreement loop, a check that each step's transcript chip names (and displays)
the run of messages its signature or MAC actually covers, a check that `Finished`
verification fails when the two sides derived from different ECDHE secrets, a gate on each
"Break this handshake" fault asserting both which verdicts it must flip *and* which it must
leave alone (the ECDHE fault must not disturb `CertificateVerify`; the in-flight byte flip
must not disturb chain validation), and a source
scan that rejects `Math.random`. The resumption phase adds 13 published values from RFC 8448
§§3–4 (resumption secret, PSK, binder derivation, early/handshake/main secrets, and the
encrypted early record), plus a generated multi-block AEAD round-trip and every replay,
fallback, and ticket-key-compromise outcome. The same gates
gate the GitHub Pages deploy (`.github/workflows/deploy.yml`). The protocol regressions also check
stale first arrivals under all five policies, zero-lifetime and exact-deadline expiry, invalid
lifetime encodings, missing/mismatched groups, and each failed full-handshake precondition.

The mutation ledger in `scripts/mutation-ledger.json` changes binder admission, replay stores,
freshness enforcement, PSK/DHE derivation, fallback, handshake eligibility, group advertisement,
expiry, and regional results. For each entry the runner proves baseline green, a non-empty source
diff, a successful build with a changed JavaScript bundle hash, failure of the single named owning
assertion, and restored source/hash/test success. Compilation, startup, navigation, skipped tests,
and test timeouts cannot count as kills. This gate runs before the Pages artifact is uploaded.

## Part of the Crypto-Lab Suite

Browse related teaching labs at
[systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/).

Related: [pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) ·
[ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/) ·
[key-exchange](https://systemslibrarian.github.io/crypto-lab-key-exchange/) ·
[pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/)

## License

[MIT](LICENSE) © Paul Clark (systemslibrarian)

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
