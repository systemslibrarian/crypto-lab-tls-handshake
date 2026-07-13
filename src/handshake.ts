/**
 * Orchestrates a complete, real TLS 1.3 (EC)DHE handshake between an in-browser
 * client and server, and records a step-by-step trace the UI walks through.
 *
 * The full 1-RTT flight sequence (RFC 8446 §2):
 *
 *   Client ── ClientHello ─────────────────────────────────────────▶ Server
 *   Client ◀── ServerHello, {EncryptedExtensions}, {Certificate},
 *              {CertificateVerify}, {Finished} ────────────────────── Server
 *   Client ── {Finished}, [Application Data] ──────────────────────▶ Server
 *
 * Messages in {braces} are encrypted under handshake traffic keys; [brackets]
 * under application traffic keys. Everything below is computed for real: X25519
 * agreement, the RFC 8446 key schedule, Ed25519 CertificateVerify, HMAC Finished
 * MACs, and AES-128-GCM record protection.
 */
import {
  AEAD_IV_BYTES,
  AES128_KEY_BYTES,
  concatBytes,
  equalBytes,
  recordNonce,
  sha256,
  toHex,
  utf8,
  x25519Keygen,
  x25519SharedSecret,
  aesGcmDecrypt,
  aesGcmEncrypt,
  randomBytes,
  type KeyPair,
} from './primitives';
import {
  deriveKeySchedule,
  deriveTrafficKeys,
  finishedMac,
  verifyFinished,
  type KeySchedule,
  type TrafficKeys,
} from './keyschedule';
import {
  certificateVerifyContent,
  issueChain,
  signCertificateVerify,
  verifyCertificateVerify,
  verifyChain,
  type CertChain,
  type ChainVerdict,
} from './certs';

// ---- Handshake message framing (real TLS handshake-message headers) ---------

const HS_CLIENT_HELLO = 0x01;
const HS_SERVER_HELLO = 0x02;
const HS_ENCRYPTED_EXTENSIONS = 0x08;
const HS_CERTIFICATE = 0x0b;
const HS_CERTIFICATE_VERIFY = 0x0f;
const HS_FINISHED = 0x14;

const TLS13 = 0x0304;
const TLS12_LEGACY = 0x0303;
const GROUP_X25519 = 0x001d;
const CIPHER_AES_128_GCM_SHA256 = 0x1301;
const SIG_ED25519 = 0x0807;

const RECORD_APPLICATION_DATA = 0x17;

function u16(value: number): Uint8Array {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}
function u24(value: number): Uint8Array {
  return new Uint8Array([(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
}
function vec(payload: Uint8Array, lenBytes: 1 | 2 | 3): Uint8Array {
  const header = lenBytes === 1 ? new Uint8Array([payload.length]) : lenBytes === 2 ? u16(payload.length) : u24(payload.length);
  return concatBytes(header, payload);
}
/** Wrap a body in the 4-byte TLS handshake header: type(1) ‖ length(3). */
function handshakeMessage(type: number, body: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([type]), u24(body.length), body);
}

function serializeClientHello(random: Uint8Array, keyShare: Uint8Array): Uint8Array {
  const keyShareEntry = concatBytes(u16(GROUP_X25519), vec(keyShare, 2));
  const body = concatBytes(
    u16(TLS12_LEGACY),
    random,
    vec(new Uint8Array(), 1), // legacy_session_id
    vec(concatBytes(u16(CIPHER_AES_128_GCM_SHA256)), 2), // cipher_suites
    new Uint8Array([1, 0]), // legacy_compression_methods: [null]
    // extensions: supported_versions(0x2b), supported_groups(0x0a), key_share(0x33)
    vec(
      concatBytes(
        concatBytes(u16(0x002b), vec(concatBytes(new Uint8Array([2]), u16(TLS13)), 2)),
        concatBytes(u16(0x000a), vec(vec(u16(GROUP_X25519), 2), 2)),
        concatBytes(u16(0x0033), vec(vec(keyShareEntry, 2), 2)),
      ),
      2,
    ),
  );
  return handshakeMessage(HS_CLIENT_HELLO, body);
}

function serializeServerHello(random: Uint8Array, keyShare: Uint8Array): Uint8Array {
  const keyShareEntry = concatBytes(u16(GROUP_X25519), vec(keyShare, 2));
  const body = concatBytes(
    u16(TLS12_LEGACY),
    random,
    vec(new Uint8Array(), 1),
    u16(CIPHER_AES_128_GCM_SHA256),
    new Uint8Array([0]), // legacy_compression_method
    vec(
      concatBytes(
        concatBytes(u16(0x002b), vec(u16(TLS13), 2)),
        concatBytes(u16(0x0033), vec(keyShareEntry, 2)),
      ),
      2,
    ),
  );
  return handshakeMessage(HS_SERVER_HELLO, body);
}

function serializeCertificate(chain: CertChain): Uint8Array {
  const entry = (subject: string, issuer: string, pub: Uint8Array, sig: Uint8Array): Uint8Array =>
    concatBytes(vec(utf8(subject), 1), vec(utf8(issuer), 1), vec(pub, 1), vec(sig, 1));
  const list = concatBytes(
    entry(chain.leaf.subject, chain.leaf.issuer, chain.leaf.publicKey, chain.leaf.signature),
    entry(chain.root.subject, chain.root.issuer, chain.root.publicKey, chain.root.signature),
  );
  return handshakeMessage(HS_CERTIFICATE, concatBytes(vec(new Uint8Array(), 1), vec(list, 3)));
}

function serializeCertificateVerify(signature: Uint8Array): Uint8Array {
  return handshakeMessage(HS_CERTIFICATE_VERIFY, concatBytes(u16(SIG_ED25519), vec(signature, 2)));
}

function serializeFinished(verifyData: Uint8Array): Uint8Array {
  return handshakeMessage(HS_FINISHED, verifyData);
}

function serializeEncryptedExtensions(): Uint8Array {
  return handshakeMessage(HS_ENCRYPTED_EXTENSIONS, vec(new Uint8Array(), 2));
}

// ---- Trace model the UI renders --------------------------------------------

export interface DerivedKeyView {
  name: string;
  preview: string;
  bytes: number;
}

export interface HandshakeStep {
  id: string;
  flight: number;
  from: 'client' | 'server';
  to: 'client' | 'server';
  title: string;
  encrypted: 'plaintext' | 'handshake' | 'application';
  /** Cryptographic operations performed at this step. */
  cryptoOps: string[];
  /** Keys/secrets newly derived or first used at this step. */
  derived: DerivedKeyView[];
  /** Security properties established once this step completes. */
  security: string[];
  bytesOnWire: number;
  /**
   * Transcript hash SHA-256(all handshake messages sent so far, up to and
   * including this one). This is the running value that CertificateVerify signs
   * and the Finished MACs cover — making transcript binding a value you watch
   * change rather than a claim in prose.
   */
  transcriptHashHex: string;
  /** True on the steps whose security rests on the transcript hash above. */
  bindsTranscript?: boolean;
}

/**
 * The Diffie–Hellman "aha": two DIFFERENT private inputs producing ONE identical
 * output. Both private keys are exposed here (masked in the UI) purely so the
 * demo can SHOW they differ; they never cross the wire in a real handshake.
 */
export interface KeyExchangeView {
  clientPrivateHex: string;
  clientPublicHex: string;
  serverPrivateHex: string;
  serverPublicHex: string;
  /** X25519(client_sk, server_pk) — the client's independently computed secret. */
  clientSecretHex: string;
  /** X25519(server_sk, client_pk) — the server's independently computed secret. */
  serverSecretHex: string;
  agrees: boolean;
}

/** One HKDF-Expand-Label derivation, decomposed into its real inputs and output. */
export interface DerivationView {
  /** Name of the output secret. */
  output: string;
  /** The secret fed in (PRK) — the parent this value branches from. */
  fromSecret: string;
  fromSecretHex: string;
  /** The literal ASCII label, e.g. "s hs traffic" (sent as "tls13 s hs traffic"). */
  label: string;
  /** Where the context (Hash(messages)) comes from, in words. */
  contextDesc: string;
  contextHex: string;
  outLen: number;
  outputHex: string;
}

export interface RecordDemo {
  plaintext: string;
  aadHex: string;
  nonceHex: string;
  ciphertextHex: string;
  ciphertextBytes: number;
  roundTripOk: boolean;
  tamperRejected: boolean;
}

export interface HandshakeTrace {
  serverName: string;
  steps: HandshakeStep[];
  schedule: KeySchedule;
  chain: CertChain;
  chainVerdict: ChainVerdict;
  certificateVerifyValid: boolean;
  serverFinishedValid: boolean;
  clientFinishedValid: boolean;
  sharedSecretAgrees: boolean;
  transcriptHelloHashHex: string;
  transcriptFullHashHex: string;
  clientHelloBytes: number;
  serverFlightBytes: number;
  clientAppKeys: TrafficKeys;
  record: RecordDemo;
  keyExchange: KeyExchangeView;
  /** The transcript hash the CertificateVerify signature is computed over. */
  certVerifyTranscriptHex: string;
  /** One fully decomposed HKDF derivation, for the schedule "show your work" view. */
  sampleDerivation: DerivationView;
}

function preview(bytes: Uint8Array, head = 6, tail = 6): string {
  if (bytes.length <= head + tail) {
    return toHex(bytes);
  }
  return `${toHex(bytes.subarray(0, head))}…${toHex(bytes.subarray(bytes.length - tail))}`;
}

function keyView(name: string, bytes: Uint8Array): DerivedKeyView {
  return { name, preview: preview(bytes), bytes: bytes.length };
}

/**
 * Run a complete, authenticated handshake and produce the full trace, including
 * a real AES-128-GCM application-data record encrypted under the derived keys.
 */
export async function runFullHandshake(serverName = 'example.com'): Promise<HandshakeTrace> {
  // --- Flight 1: ClientHello (client generates an ephemeral X25519 keypair) ---
  const clientKeys: KeyPair = x25519Keygen();
  const clientRandom = randomBytes(32);
  const clientHello = serializeClientHello(clientRandom, clientKeys.publicKey);

  // --- Flight 2: server side ---
  const serverKeys: KeyPair = x25519Keygen();
  const serverRandom = randomBytes(32);
  const serverHello = serializeServerHello(serverRandom, serverKeys.publicKey);

  // Both sides compute the SAME X25519 shared secret independently.
  const serverShared = x25519SharedSecret(serverKeys.secretKey, clientKeys.publicKey);
  const clientShared = x25519SharedSecret(clientKeys.secretKey, serverKeys.publicKey);
  const sharedSecretAgrees = equalBytes(serverShared, clientShared);

  const chain = issueChain(serverName);

  // Transcript hashes are taken over the running handshake-message concatenation.
  const thHello = await sha256(concatBytes(clientHello, serverHello));

  const encryptedExtensions = serializeEncryptedExtensions();
  const certificate = serializeCertificate(chain);

  // CertificateVerify signs Hash(CH..Certificate) with the leaf private key.
  const thForCertVerify = await sha256(concatBytes(clientHello, serverHello, encryptedExtensions, certificate));
  const certVerifySig = signCertificateVerify(thForCertVerify, chain.leafSecretKey);
  const certificateVerify = serializeCertificateVerify(certVerifySig);
  const certificateVerifyValid = verifyCertificateVerify(thForCertVerify, certVerifySig, chain.leaf.publicKey);

  // Key schedule needs the app-phase transcript hash too, but that depends on the
  // server Finished, which depends on the handshake secret. So derive handshake
  // traffic secrets first (they only need thHello), build server Finished, then
  // derive the rest. We compute the schedule in two reads of deriveKeySchedule:
  // first with a placeholder app hash to get the handshake secrets, then again
  // with the real app-phase hash. Cheaper and clearer: derive handshake secrets
  // directly via deriveKeySchedule using thHello for both, then recompute.
  const provisional = await deriveKeySchedule(serverShared, thHello, thHello);
  const sHsBase = provisional.serverHandshakeTrafficSecret;

  // Server Finished MAC covers Hash(CH..CertificateVerify).
  const thForServerFinished = await sha256(
    concatBytes(clientHello, serverHello, encryptedExtensions, certificate, certificateVerify),
  );
  const serverFinishedData = await finishedMac(sHsBase, thForServerFinished);
  const serverFinished = serializeFinished(serverFinishedData);
  // Client verifies the server Finished with the server's handshake traffic secret.
  const serverFinishedValid = await verifyFinished(sHsBase, thForServerFinished, serverFinishedData);

  // Now the application-phase transcript hash: Hash(CH..server Finished).
  const thAfterServerFinished = await sha256(
    concatBytes(clientHello, serverHello, encryptedExtensions, certificate, certificateVerify, serverFinished),
  );
  const schedule = await deriveKeySchedule(serverShared, thHello, thAfterServerFinished);

  // --- Flight 3: client Finished covers Hash(CH..server Finished) ---
  const clientFinishedData = await finishedMac(schedule.clientHandshakeTrafficSecret, thAfterServerFinished);
  const clientFinished = serializeFinished(clientFinishedData);
  const clientFinishedValid = await verifyFinished(
    schedule.clientHandshakeTrafficSecret,
    thAfterServerFinished,
    clientFinishedData,
  );

  // --- Application data: real AES-128-GCM under the client app traffic secret ---
  const clientAppKeys = await deriveTrafficKeys(schedule.clientApplicationTrafficSecret);
  const record = await encryptApplicationRecord(
    clientAppKeys,
    `GET / HTTP/1.1\r\nHost: ${serverName}\r\n\r\n`,
  );

  // Running transcript hash after each handshake message. This is the exact
  // value CertificateVerify signs and the Finished MACs cover; exposing it per
  // step lets the UI show it grow as the conversation unfolds.
  const clientFinishedTh = await sha256(
    concatBytes(clientHello, serverHello, encryptedExtensions, certificate, certificateVerify, serverFinished, clientFinished),
  );
  const thByStepId: Record<string, string> = {
    'client-hello': toHex(await sha256(clientHello)),
    'server-hello': toHex(thHello),
    'encrypted-extensions': toHex(await sha256(concatBytes(clientHello, serverHello, encryptedExtensions))),
    certificate: toHex(thForCertVerify),
    'certificate-verify': toHex(thForCertVerify), // CV signs Hash(CH..Certificate); transcript unchanged until it is appended
    'server-finished': toHex(thForServerFinished),
    'client-finished': toHex(clientFinishedTh),
    'application-data': toHex(clientFinishedTh),
  };

  // One fully decomposed derivation for the "show your work" HKDF view: the
  // server handshake traffic secret. Real inputs, real output.
  const sampleDerivation: DerivationView = {
    output: 'server_handshake_traffic_secret',
    fromSecret: 'Handshake Secret',
    fromSecretHex: toHex(schedule.handshakeSecret),
    label: 's hs traffic',
    contextDesc: 'Hash(ClientHello ‖ ServerHello) — the "transcript so far"',
    contextHex: toHex(thHello),
    outLen: schedule.serverHandshakeTrafficSecret.length,
    outputHex: toHex(schedule.serverHandshakeTrafficSecret),
  };

  const keyExchange: KeyExchangeView = {
    clientPrivateHex: toHex(clientKeys.secretKey),
    clientPublicHex: toHex(clientKeys.publicKey),
    serverPrivateHex: toHex(serverKeys.secretKey),
    serverPublicHex: toHex(serverKeys.publicKey),
    clientSecretHex: toHex(clientShared),
    serverSecretHex: toHex(serverShared),
    agrees: sharedSecretAgrees,
  };

  const stepsBase: Omit<HandshakeStep, 'transcriptHashHex'>[] = [
    {
      id: 'client-hello',
      flight: 1,
      from: 'client',
      to: 'server',
      title: 'ClientHello',
      encrypted: 'plaintext',
      cryptoOps: [
        'Generate ephemeral X25519 keypair (forward-secret; discarded after the session)',
        'Advertise supported_versions=TLS 1.3, cipher TLS_AES_128_GCM_SHA256, group x25519',
        'Send the X25519 public key as a key_share extension',
      ],
      derived: [keyView('client X25519 public key', clientKeys.publicKey)],
      security: ['No secrets yet — ClientHello is sent in the clear.'],
      bytesOnWire: clientHello.length,
    },
    {
      id: 'server-hello',
      flight: 2,
      from: 'server',
      to: 'client',
      title: 'ServerHello',
      encrypted: 'plaintext',
      cryptoOps: [
        'Generate ephemeral X25519 keypair; reply with its public key',
        'Compute ECDHE shared secret = X25519(server_sk, client_pk)',
        'Run the key schedule to the Handshake Secret and derive handshake traffic keys',
      ],
      derived: [
        keyView('ECDHE shared secret', serverShared),
        keyView('handshake secret', schedule.handshakeSecret),
        keyView('server handshake traffic secret', schedule.serverHandshakeTrafficSecret),
        keyView('client handshake traffic secret', schedule.clientHandshakeTrafficSecret),
      ],
      security: [
        'Both sides now share a secret derived from ephemeral keys → forward secrecy.',
        'Everything after ServerHello is encrypted under handshake traffic keys.',
      ],
      bytesOnWire: serverHello.length,
    },
    {
      id: 'encrypted-extensions',
      flight: 2,
      from: 'server',
      to: 'client',
      title: 'EncryptedExtensions',
      encrypted: 'handshake',
      cryptoOps: ['Send remaining negotiated parameters, now encrypted under the handshake key'],
      derived: [],
      security: ['First encrypted handshake message — protects negotiated extensions from passive eavesdroppers.'],
      bytesOnWire: encryptedExtensions.length,
    },
    {
      id: 'certificate',
      flight: 2,
      from: 'server',
      to: 'client',
      title: 'Certificate',
      encrypted: 'handshake',
      cryptoOps: [
        'Send the server certificate chain (leaf ‖ root CA)',
        'Client validates: leaf signed by root, root matches a trusted anchor',
      ],
      derived: [keyView('leaf public key (Ed25519)', chain.leaf.publicKey)],
      security: ['Identity claimed. Not yet proven — anyone can copy a public certificate.'],
      bytesOnWire: certificate.length,
    },
    {
      id: 'certificate-verify',
      flight: 2,
      from: 'server',
      to: 'client',
      title: 'CertificateVerify',
      encrypted: 'handshake',
      cryptoOps: [
        'Server signs Hash(ClientHello..Certificate) with the leaf PRIVATE key (Ed25519)',
        'Client verifies the signature with the public key from the certificate',
      ],
      derived: [keyView('CertificateVerify signature', certVerifySig)],
      security: [
        'Authentication achieved: only the real key holder could sign THIS transcript.',
        'This is what defeats a man-in-the-middle — see the MITM panel below.',
      ],
      bytesOnWire: certificateVerify.length,
      bindsTranscript: true,
    },
    {
      id: 'server-finished',
      flight: 2,
      from: 'server',
      to: 'client',
      title: 'Finished (server)',
      encrypted: 'handshake',
      cryptoOps: [
        'finished_key = HKDF-Expand-Label(server_hs_traffic, "finished", "", 32)',
        'verify_data = HMAC(finished_key, Hash(ClientHello..CertificateVerify))',
      ],
      derived: [keyView('server Finished verify_data', serverFinishedData)],
      security: ['Handshake integrity: the entire transcript so far is MAC-bound. Tampering is detected.'],
      bytesOnWire: serverFinished.length,
      bindsTranscript: true,
    },
    {
      id: 'client-finished',
      flight: 3,
      from: 'client',
      to: 'server',
      title: 'Finished (client)',
      encrypted: 'handshake',
      cryptoOps: [
        'Client verifies the server Finished, then derives the Master Secret and app traffic secrets',
        'verify_data = HMAC(client finished_key, Hash(ClientHello..server Finished))',
      ],
      derived: [
        keyView('master secret', schedule.masterSecret),
        keyView('client application traffic secret', schedule.clientApplicationTrafficSecret),
        keyView('server application traffic secret', schedule.serverApplicationTrafficSecret),
        keyView('client Finished verify_data', clientFinishedData),
      ],
      security: ['Handshake complete and mutually confirmed. Both sides hold the same application keys.'],
      bytesOnWire: clientFinished.length,
    },
    {
      id: 'application-data',
      flight: 3,
      from: 'client',
      to: 'server',
      title: 'Application Data',
      encrypted: 'application',
      cryptoOps: [
        'Derive record key/iv: HKDF-Expand-Label(client_ap_traffic, "key"/"iv", "", …)',
        'Encrypt with AES-128-GCM; per-record nonce = write_iv XOR sequence number',
      ],
      derived: [keyView('client record key (AES-128)', clientAppKeys.key), keyView('client record IV', clientAppKeys.iv)],
      security: ['Confidentiality + integrity for application traffic via authenticated encryption (AEAD).'],
      bytesOnWire: record.ciphertextBytes,
    },
  ];

  const steps: HandshakeStep[] = stepsBase.map((s) => ({
    ...s,
    transcriptHashHex: thByStepId[s.id] ?? '',
  }));

  const serverFlightBytes =
    serverHello.length +
    encryptedExtensions.length +
    certificate.length +
    certificateVerify.length +
    serverFinished.length;

  return {
    serverName,
    steps,
    schedule,
    chain,
    chainVerdict: verifyChain(chain, chain.rootPublicKey),
    certificateVerifyValid,
    serverFinishedValid,
    clientFinishedValid,
    sharedSecretAgrees,
    transcriptHelloHashHex: toHex(thHello),
    transcriptFullHashHex: toHex(thAfterServerFinished),
    clientHelloBytes: clientHello.length,
    serverFlightBytes,
    clientAppKeys,
    record,
    keyExchange,
    certVerifyTranscriptHex: toHex(thForCertVerify),
    sampleDerivation,
  };
}

async function encryptApplicationRecord(keys: TrafficKeys, message: string): Promise<RecordDemo> {
  const plaintextBytes = utf8(message);
  // TLS 1.3 inner plaintext appends the real content type, then AEAD-seals it.
  const inner = concatBytes(plaintextBytes, new Uint8Array([RECORD_APPLICATION_DATA]));
  const seq = 0;
  const nonce = recordNonce(keys.iv, seq);
  // AAD is the record header: type(0x17) ‖ legacy_version(0x0303) ‖ length.
  const aeadLen = inner.length + 16; // GCM tag is 16 bytes
  const aad = concatBytes(new Uint8Array([RECORD_APPLICATION_DATA]), u16(TLS12_LEGACY), u16(aeadLen));

  const ciphertext = await aesGcmEncrypt(keys.key, nonce, inner, aad);

  let roundTripOk = false;
  try {
    const decrypted = await aesGcmDecrypt(keys.key, nonce, ciphertext, aad);
    roundTripOk = equalBytes(decrypted, inner);
  } catch {
    roundTripOk = false;
  }

  // Flip one ciphertext byte; GCM's tag must reject it.
  let tamperRejected = false;
  const tampered = Uint8Array.from(ciphertext);
  tampered[0] ^= 0x01;
  try {
    await aesGcmDecrypt(keys.key, nonce, tampered, aad);
    tamperRejected = false;
  } catch {
    tamperRejected = true;
  }

  return {
    plaintext: message,
    aadHex: toHex(aad),
    nonceHex: toHex(nonce),
    ciphertextHex: toHex(ciphertext),
    ciphertextBytes: ciphertext.length,
    roundTripOk,
    tamperRejected,
  };
}

// ---- Man-in-the-middle demonstration ---------------------------------------

export interface MitmResult {
  /** Attacker completes ECDHE with the client (it always can — keys are public). */
  keyExchangeSucceeded: boolean;
  /** Attacker presents the REAL leaf cert it copied off the wire. Chain still validates. */
  presentedRealCertificate: boolean;
  /** Attacker has no leaf private key, so its CertificateVerify must fail. */
  certificateVerifyForged: boolean;
  certificateVerifyAccepted: boolean;
  /** The connection is only safe if the forged auth is rejected. */
  attackBlocked: boolean;
  explanation: string[];
  /** Transcript hash of the genuine client<->server conversation. */
  genuineTranscriptHex: string;
  /** Transcript hash of the client<->attacker conversation — a DIFFERENT value. */
  attackerTranscriptHex: string;
  /** True: the two transcripts differ, so a signature over one can't satisfy the other. */
  transcriptsDiffer: boolean;
}

/**
 * Model an active MITM. The attacker terminates the client's connection, does a
 * fresh ECDHE (trivially possible — public keys are public), and replays the
 * genuine server certificate it observed. The one thing it cannot do is sign the
 * CertificateVerify over the live transcript with the leaf's private key. The
 * client's signature check therefore fails and the handshake aborts.
 */
export async function runMitmAttempt(serverName = 'example.com'): Promise<MitmResult> {
  const chain = issueChain(serverName);

  // Client and attacker complete an ECDHE just fine.
  const client = x25519Keygen();
  const attacker = x25519Keygen();
  const server = x25519Keygen();
  const attackerShared = x25519SharedSecret(attacker.secretKey, client.publicKey);
  const keyExchangeSucceeded = attackerShared.length === 32;

  // Two DIFFERENT conversations happen: the genuine client<->server transcript,
  // and the client<->attacker transcript. Because the attacker injected its own
  // ephemeral key_share, the two transcript hashes differ — so a signature over
  // one is meaningless against the other. This is the concrete reason MITM fails.
  const genuineTranscript = await sha256(concatBytes(client.publicKey, server.publicKey, utf8(serverName)));
  const attackerTranscript = await sha256(concatBytes(client.publicKey, attacker.publicKey, utf8(serverName)));
  const transcriptsDiffer = !equalBytes(genuineTranscript, attackerTranscript);

  // The transcript the client will actually verify the signature against is the
  // attacker-side one (that is the conversation the client had).
  const transcriptHash = attackerTranscript;

  // Attacker copies the real leaf certificate (public). The chain validates,
  // because the certificate itself is genuine and root-signed.
  const presentedRealCertificate = verifyChain(chain, chain.rootPublicKey).valid;

  // But the attacker lacks the leaf private key. Its best move is to sign with
  // its OWN key — which won't verify against the leaf's public key.
  const forgedSig = signCertificateVerify(transcriptHash, attacker.secretKey);
  const certificateVerifyAccepted = verifyCertificateVerify(transcriptHash, forgedSig, chain.leaf.publicKey);

  // Sanity: the genuine private key WOULD have verified, proving the check works.
  const genuineSig = signCertificateVerify(transcriptHash, chain.leafSecretKey);
  const genuineWouldVerify = verifyCertificateVerify(transcriptHash, genuineSig, chain.leaf.publicKey);

  const attackBlocked = !certificateVerifyAccepted && genuineWouldVerify;

  return {
    keyExchangeSucceeded,
    presentedRealCertificate,
    certificateVerifyForged: true,
    certificateVerifyAccepted,
    attackBlocked,
    genuineTranscriptHex: toHex(genuineTranscript),
    attackerTranscriptHex: toHex(attackerTranscript),
    transcriptsDiffer,
    explanation: [
      'Key exchange with the attacker succeeds — ephemeral public keys are public, so ECDHE alone proves nothing.',
      'The attacker even replays the real, root-signed server certificate, so chain validation passes.',
      'CertificateVerify is the trap: it must be signed over THIS transcript with the leaf private key.',
      'The attacker has no leaf private key, so its signature fails verification and the client aborts.',
      'Lesson: authentication (signatures), not key exchange, is what binds the session to the real server.',
    ],
  };
}

/** Exposed for tests: the exact CertificateVerify content the server signs. */
export const __testHooks = { certificateVerifyContent, AES128_KEY_BYTES, AEAD_IV_BYTES };
