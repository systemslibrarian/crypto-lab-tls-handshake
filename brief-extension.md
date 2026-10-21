# Extension brief — `crypto-lab-tls-handshake`

**2026-10-20. Extension to a live lab; no new repository.** Written against
`crypto-lab-tls-handshake` at `3da1dab9287f` and `audits/_MASTER-TEMPLATE.md` (catalog
`20cb434d89e4`). Template §5: "Extend, never restructure." Source of the gap: Boneh–Shoup v0.6
§21.10.1 "Authenticated key exchange with preshared keys" (tickets, forward secrecy of
resumption, and 0-RTT replay).

**Verdict: extension — one new section, "Resumption & 0-RTT", after the Record Layer section.**

## What the lab has now

- **Key schedule** `src/keyschedule.ts`: `deriveKeySchedule(sharedSecret, helloHash,
  toServerFinishedHash)` (`:58–118`) computes Early Secret as `hkdfExtract(ZEROS, ZEROS)`
  (`:66`) — the no-PSK constant — then Handshake, Main, the four traffic secrets and the
  exporter. The header comment (`:20–22`) says the demo "uses the (EC)DHE-only path (no PSK /
  0-RTT)". `deriveTrafficKeys` (`:124`), `finishedMac` / `verifyFinished` (`:136–148`).
- **Primitives** `src/primitives.ts`: `hkdfExtract` (`:152`), `hkdfExpand` (`:179`),
  `hkdfExpandLabel` (`:203`), `deriveSecret` (`:232`), `aesGcmEncrypt` / `aesGcmDecrypt`
  (`:241–278`), `recordNonce` (`:280`), X25519 / Ed25519 via `@noble/curves` (`:105–137`).
  Reuse these; do not add a second HKDF.
- **Handshake** `src/handshake.ts`: `serializeClientHello` (`:85–104`) emits only
  supported_versions, supported_groups and key_share; `runFullHandshake` (`:336`);
  `encryptApplicationRecord` (`:712–755`); MITM strategies (`:757–819`).
- **Page** `src/main.ts` `render()` (`:584–615`): overview, simulator, key exchange, auth,
  schedule (§5, `:368`), record layer (§6, `:446`), comparison (§7, `:471`), scope (§8, `:537`).
  Verdicts render through `pill(ok, label, alarmOnFail)` (`:47`). The scope list at `:521` says
  the demo does **not** model "PSK and session resumption, 0-RTT early data, HelloRetryRequest,
  …"; the schedule row at `:381` reads "Early Secret (constant — no PSK)".
- **Tests:** `npm test` runs `tsx scripts/phase-checks.ts all` — phases keyschedule (RFC 8448 §3
  "derived" vector and the no-PSK Early Secret, `:69–80`), auth, record, handshake, discipline,
  rfc5869. Playwright `e2e/claims.spec.ts` (12 tests, e.g. `:143` honest session, `:524` record
  layer, `:560` key schedule), helpers in `e2e/gate.ts` (`boot` at `:123`). No mutation script.
- The lab cites RFC 9846 (TLS 1.3, obsoletes RFC 8446) throughout; keep doing so.

## What to add

New section **"7 Resumption & 0-RTT"** after §6; renumber Comparison → 8 and Scope → 9.
Plain intro: "After a full handshake the server can hand the client a ticket. Next time, the
client can skip the certificate check — and can even send data in its very first message. That
first-message data is fast, and it can be replayed."

1. **Act A — the ticket and the PSK.** After the existing full handshake, the server sends a
   NewSessionTicket (RFC 9846 §4.7.1; RFC 8446 §4.6.1): ticket_lifetime (at most 604800 s —
   seven days, as B–S also state), ticket_age_add, ticket_nonce, an opaque ticket, and the
   early_data extension (confirm the 604800-second ceiling in RFC 9846 §4.7.1 before printing
   the number). Derive the resumption secret with Derive-Secret(Main Secret,
   "res master", Hash(CH..client Finished)) and the PSK as HKDF-Expand-Label(resumption secret,
   "resumption", ticket_nonce, Hash.length). Use RFC 9846's names for the secrets and confirm
   them in its §7.1 and §4.7.1 before writing labels. The ticket is this lab's own format —
   AES-128-GCM under a server-only ticket key (STEK) over the PSK and state, labelled as
   modelled, since the RFC leaves ticket contents to the server (B–S §21.10.1 "Tickets").
2. **Act B — the resumption handshake.** A second ClientHello with psk_key_exchange_modes
   (RFC 9846 §4.3.9), key_share, early_data (§4.3.10) and pre_shared_key **last** (§4.3.11),
   carrying the identity and obfuscated_ticket_age. The binder: binder_key =
   Derive-Secret(Early Secret, "res binder", ""), finished_key = HKDF-Expand-Label(binder_key,
   "finished", "", Hash.length), binder = HMAC(finished_key, Transcript-Hash(truncated
   ClientHello)) — the PSK Binder subsection of RFC 9846 §4.3.11 (RFC 8446 §4.2.11.2; confirm
   the 9846 subsection number). Early Secret is now HKDF-Extract(0, PSK). Mode toggle:
   - `psk_dhe_ke` — a fresh X25519 share is mixed into the Handshake Secret;
   - `psk_ke` — "PSK-only key establishment. In this mode, the server MUST NOT supply a
     'key_share' value" (§4.3.9): the (EC)DHE input is the all-zero string.
   Break-it-yourself: flip a byte in the offered identity → the server's binder check fails.
3. **Act C — forward secrecy of resumption.** Record one `psk_ke` and one `psk_dhe_ke` resumed
   session, then **Leak the ticket key**: the attacker decrypts the recorded ticket, recovers the
   PSK, and reads the `psk_ke` session's 1-RTT data; the `psk_dhe_ke` session's 1-RTT data stays
   sealed (B–S §21.10.1 "Forward secrecy"). Then show what `psk_dhe_ke` does **not** protect:
   the recorded 0-RTT data of that same session decrypts, because its key comes from the PSK
   alone — RFC 9846 §2.3: "The protocol does not provide any forward secrecy guarantees for this
   data."
4. **Act D — 0-RTT replay.** client_early_traffic_secret = Derive-Secret(Early Secret,
   "c e traffic", ClientHello); the early-data record carries B–S's example, a bill payment. The
   attacker records ClientHello + early data and replays it. Server configurations, selectable:
   - **no anti-replay** (marked broken): the payment executes twice;
   - **single-use tickets** (RFC 9846 §8.1): the second use of the ticket is refused;
   - **ClientHello recording** (§8.2): the second arrival at the same server is refused — and,
     B–S's distributed case, replaying into a second server instance that shares the ticket key
     but not the recording store succeeds;
   - **freshness check** (§8.3) using obfuscated_ticket_age: a replay outside the window is
     refused, one inside it is not — the page says the window narrows replay but does not
     prevent it;
   - **server ignores 0-RTT**: the client re-sends the request after the handshake, where the
     server nonce makes replay fail (B–S's closing paragraph).
   Prose only: B–S's response-length side channel (repeating a balance query to watch reply
   size) and RFC 9846 Appendix F.5.

Why it belongs here and not in a new lab: the full handshake, key schedule, transcript and
record layer it extends are already here, and the lab's own scope list names exactly these
features as the missing piece.

## SECURITY / CORRECTNESS INVARIANTS

1. Every new secret goes through the existing `hkdfExtract` / `hkdfExpandLabel` /
   `deriveSecret`. A PSK-aware schedule is a new function (e.g. `deriveResumptionSchedule` in a
   new `src/resumption.ts`) or an optional `psk` argument whose default reproduces today's
   outputs bit for bit; the existing `phase-checks.ts` assertions must pass unchanged.
2. `psk_ke` and "no anti-replay" are deliberately weak configurations: isolated, never the
   default, visibly marked.
3. The binder is verified before any early data is decrypted; a binder failure aborts with the
   field named and never yields partial plaintext.
4. The attacker uses only recorded wire bytes and, in Act C, the leaked ticket key; a unit test
   asserts the attack module imports no other secret.
5. The replay verdict reports what the modelled server actually executed (a counter of
   executed payments), not a flag the attack sets.
6. Ticket keys, PSKs and tickets live in memory for the page session only.

## ARCHITECTURE

`src/ticket.ts` (NewSessionTicket encode/decode, STEK seal/open), `src/resumption.ts` (PSK
derivation, binder, early secrets, PSK-aware schedule), `src/clienthello-psk.ts` (resumption
ClientHello with the four extensions and the truncation used for the binder), `src/zerortt.ts`
(early-data records with `recordNonce`), `src/antireplay.ts` (the five server configurations),
`src/attack/replay.ts`, `src/attack/stek-leak.ts`. UI in a new `resumptionSection(t)` placed
after `recordSection(t)` in `render()`.

## UI

A ticket card (fields with hover definitions), a mode toggle (`psk_dhe_ke` / `psk_ke`), a
schedule view mirroring §5's rows but rooted in the PSK, and a replay console: **Record**,
**Replay**, a server-configuration selector, two server tiles ("region A", "region B") for the
recording case, and an executed-payments counter per tile. Stacks below 640px.

## VISUAL SEMANTICS

A replay that executes reads **ALARM — EXECUTED TWICE**; a STEK leak that exposes data reads
**ALARM — PAST SESSION READ**; `psk_dhe_ke` holding while its 0-RTT data is exposed is a split
verdict. Use the existing `pill(…, alarmOnFail)` convention; icon + text + colour.

## EDGE CASES

- Ticket presented after its lifetime → server falls back to a full handshake; page says why.
- obfuscated_ticket_age outside tolerance → server "SHOULD proceed with the handshake but reject
  0-RTT" (§4.3.10); show the 1-RTT fallback.
- Tampered ticket ciphertext → STEK AEAD rejects; full handshake.
- Binder computed over the untruncated ClientHello (a common bug) → mismatch; the page shows
  which bytes were included.
- `psk_ke` offered but the server only allows `psk_dhe_ke` → server picks a full handshake.

## Tests

- **KATs, new `resumption` phase in `scripts/phase-checks.ts`, copied from the primary text of
  RFC 8448** (TLS_AES_128_GCM_SHA256 and x25519 — the same suite and group the lab already
  uses): from §3, the resumption secret and the "tls13 resumption" expansion that is the PSK;
  from §4 "Resumed 0-RTT Handshake", the early secret extracted from that PSK, the binder
  ("finished" over the binder hash, computed from the RFC's own ClientHello bytes truncated
  before the binders), the client early traffic secret, and the later handshake secrets that mix
  in the §4 ECDHE value. Locator prefixes only, from a summarised fetch — copy every full value
  from the RFC itself: PSK `4e cd 0e b6…`, early secret `9b 21 88 e9…`, client early traffic
  secret `3f bb e6 a6…`, binder `3a dd 4f b2…`. If the §4 trace includes the encrypted
  early-data record, decrypt it with the lab's `aesGcmDecrypt` and assert the plaintext — that
  record is longer than one AES block.
- **Vitest-equivalent checks in phase-checks:** every replay configuration produces the
  documented accept/refuse outcome; the STEK leak decrypts `psk_ke` 1-RTT data and `psk_dhe_ke`
  0-RTT data but not `psk_dhe_ke` 1-RTT data; the PSK-less schedule is bit-identical to today's.
- **e2e/claims.spec.ts additions:** recompute the binder in the test from the truncated
  ClientHello hex and PSK shown on screen and compare to the rendered binder; assert the
  executed-payments counter equals the number of accepted replays listed in the log; assert
  region B's verdict differs from region A's only in the recording configuration; retirement and
  no-op guard for the mode toggle.
- **§4.1c:** one mutation per new pill (binder check, each server configuration's verdict, both
  STEK-leak verdicts, the 1-RTT fallback), five steps each.
- **§4.1d negative claim:** "A valid PSK binder and a valid ticket do not make 0-RTT data
  replay-safe." Evidence fixture: Act D, no anti-replay, after one replay — binder VALID, ticket
  VALID, early data DECRYPTED, executed-payments = 2. Verdict shape: `AUTHENTICATED — AND
  REPLAYED`.

## README and card follow-up

What It Is gains resumption and 0-RTT; the section list gains §7 and renumbers; "What Can Go
Wrong" gains 0-RTT replay and `psk_ke`'s missing forward secrecy. Update every restatement of
the old scope: `src/main.ts:521` (move PSK, resumption and 0-RTT out of "does NOT model"; keep
HelloRetryRequest and the rest), `src/keyschedule.ts:20–22`, `src/main.ts:381` (that row stays
correct for the full handshake — label it so), and the README test description. Handoff: card
copy may mention 0-RTT replay; chip candidates per the chip rule; do not edit `../crypto-lab`.

## Do not touch

The existing full handshake, its RFC 8448 §3 assertions, the MITM strategies, the record-layer
section, the theme pin, header and deploy workflow.

## Sources

- D. Boneh, V. Shoup, *A Graduate Course in Applied Cryptography*, v0.6, §21.10.1 —
  https://toc.cryptobook.us/
- RFC 9846, The Transport Layer Security (TLS) Protocol Version 1.3 (obsoletes RFC 8446):
  §2.3, §4.3.9, §4.3.10, §4.3.11, §4.7.1, §7.1, §8.1–8.3, Appendix F.5 —
  https://www.rfc-editor.org/rfc/rfc9846
- RFC 8446 §4.2.11.2 (PSK Binder; for cross-reference) — https://www.rfc-editor.org/rfc/rfc8446
- RFC 8448, Example Handshake Traces for TLS 1.3, §3 and §4 —
  https://www.rfc-editor.org/rfc/rfc8448
