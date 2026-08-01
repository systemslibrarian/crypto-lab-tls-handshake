# crypto-lab-tls-handshake

> **TLS 1.3 Handshake** — an interactive, step-by-step walkthrough of how a modern
> HTTPS connection is established. Real WebCrypto + real primitives, no backend.

## What It Is

A browser demo of a complete **TLS 1.3** (RFC 8446) handshake, run entirely in the
page with no server. It uses genuine cryptographic primitives — **X25519** ephemeral
key exchange, **Ed25519** certificate-chain and `CertificateVerify` signatures, the
**HKDF** key schedule (`HKDF-Extract` / `HKDF-Expand-Label` / `Derive-Secret`), HMAC
`Finished` MACs, and **AES-128-GCM** record protection. It surfaces the running
**transcript hash** as a first-class value so you can see exactly what each signature and
MAC is bound to. It is an honest educational simulation of the protocol's message flow and
key schedule, not a hardened TLS stack:
it implements the `(EC)DHE`-only full handshake and deliberately omits PSK/0-RTT,
HelloRetryRequest, client authentication, X.509 encoding, and every name/validity/revocation
check a real client performs. The page states those boundaries itself, in a Scope panel.

## When to Use It

- **Teaching how a real handshake fits together** — students who learned Diffie–Hellman, signatures, and AEAD in isolation can see them combine into one protocol.
- **Showing why authentication, not key exchange, stops a MITM** — the attack panel runs three different attacker strategies against the *current session's* real chain and real transcript, and shows which check each one trips: reusing the server's certificate fails the signature, signing with the attacker's own key fails the trust anchor, and relaying unchanged passes every check while gaining the attacker nothing.
- **Explaining forward secrecy concretely** — the server's Ed25519 certificate key persists across sessions while the X25519 keys are generated per session and discarded, so you can press *New session* and watch the long-term key stay put while every derived secret changes.
- **Walking the TLS 1.3 key schedule** — every secret in the RFC 8446 §7.1 tree is shown as the real HKDF output for the current session.
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
leaf key stays the same. A closing **Scope** panel states in the page itself what is
modelled faithfully and what is not: the certificate chain is not X.509 (so the
`Certificate` step's byte count is this demo's encoding), no hostname/SAN, validity, or
revocation check exists, PSK/0-RTT/HelloRetryRequest are omitted, nothing is negotiated,
and only the application-data record is actually AEAD-sealed.

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
npm test            # RFC 8448 HKDF vector + key schedule, auth/MITM, AEAD, end-to-end handshake gates
npm run build       # type-check + production bundle
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
scan that rejects `Math.random`. The same gates
gate the GitHub Pages deploy (`.github/workflows/deploy.yml`).

## Part of the Crypto-Lab Suite

> One of 170+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

Related: [pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) ·
[ssh-handshake](https://systemslibrarian.github.io/crypto-lab-ssh-handshake/) ·
[key-exchange](https://systemslibrarian.github.io/crypto-lab-key-exchange/) ·
[pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/)

## License

[MIT](LICENSE) © Paul Clark (systemslibrarian)

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*
