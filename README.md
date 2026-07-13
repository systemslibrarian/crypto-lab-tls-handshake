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
HelloRetryRequest, client authentication, and full X.509 parsing.

## When to Use It

- **Teaching how a real handshake fits together** — students who learned Diffie–Hellman, signatures, and AEAD in isolation can see them combine into one protocol.
- **Showing why authentication, not key exchange, stops a MITM** — the built-in attack panel demonstrates an attacker completing key exchange yet failing to forge `CertificateVerify`.
- **Explaining forward secrecy concretely** — ephemeral X25519 keys are generated per session and discarded, so the key schedule visibly does not depend on any long-term secret.
- **Walking the TLS 1.3 key schedule** — every secret in the RFC 8446 §7.1 tree is shown as the real HKDF output for the current session.
- **Do NOT use it as a TLS library.** It is an educational tool; JavaScript here is not constant-time and the chain validation is intentionally minimal. For production, use a vetted TLS implementation.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-tls-handshake](https://systemslibrarian.github.io/crypto-lab-tls-handshake/)**

Step through the eight-message handshake one flight at a time (Step / Back / Auto-play,
arrow keys, or click any message); a labelled packet flies along the wire, tinted by its
encryption layer (cleartext / handshake-key / app-key). Each step shows what cryptographic
operation runs, which keys are derived, and — as a **live transcript-hash chip** — the
exact SHA-256 that `CertificateVerify` signs and the `Finished` MACs cover, so transcript
binding is a value you watch change rather than a claim. The **key-exchange panel** shows
both sides fully: each combines its own (masked) private key with the peer's public key,
and the two independently-computed 32-byte secrets are stacked with a **byte-level match
highlight** — different private inputs, byte-identical output, the Diffie–Hellman "aha".
The authentication panel validates the certificate chain and lets you launch a **MITM
attack** that gets blocked, now showing the attacker's transcript hash *differing* from the
genuine one so the signature failure is grounded in a value. The key-schedule panel renders
the live HKDF tree plus an expandable **"show one derivation in full"** view — inputs →
`HKDF-Expand-Label(secret, label, context)` → output, with byte-length bars. The
record-layer panel encrypts a real HTTP request with AES-128-GCM and proves tampering is
rejected. Inline dotted-underline definitions cover ECDHE, AEAD, AAD, IV/nonce, and the
transcript hash. Press **New session** for fresh ephemeral keys.

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
accept/reject and `CertificateVerify` forge-rejection, the MITM-blocked invariant,
AES-128-GCM round-trip + tamper rejection + per-record nonce uniqueness, a 40-session
end-to-end agreement loop, and a source scan that rejects `Math.random`. The same gates
gate the GitHub Pages deploy (`.github/workflows/deploy.yml`).

## Part of the Crypto-Lab Suite

> One of 60+ live browser demos at
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
