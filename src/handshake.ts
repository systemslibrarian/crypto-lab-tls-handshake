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
  ed25519Keygen,
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
  serverIdentity,
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

/**
 * Everything the MITM exhibit needs to attack THIS session rather than a
 * freshly-invented one: the actual bytes each party sent, the actual keys, and
 * the actual certificate chain and CertificateVerify signature.
 *
 * This is deliberately the session's own material. An earlier version ran the
 * MITM against a brand-new keypair and a brand-new chain and then labelled a
 * three-field hash of (client_pk ‖ server_pk ‖ serverName) "the real
 * client↔server transcript" — naming a conversation that never happened, using
 * a value that was not a TLS transcript.
 */
export interface SessionMaterials {
  serverName: string;
  /** The exact ClientHello bytes this session sent. */
  clientHello: Uint8Array;
  /** The client's ephemeral X25519 keypair for this session. */
  clientKeys: KeyPair;
  /** The genuine server's ephemeral X25519 public key. */
  serverPublicKey: Uint8Array;
  /** The exact ServerHello bytes the genuine server sent. */
  serverHello: Uint8Array;
  encryptedExtensions: Uint8Array;
  /** The exact Certificate message bytes carrying the genuine chain. */
  certificate: Uint8Array;
  chain: CertChain;
  /** Hash(ClientHello..Certificate) — the value CertificateVerify really signed. */
  certVerifyTranscript: Uint8Array;
  /** The genuine CertificateVerify signature over that transcript. */
  certVerifySignature: Uint8Array;
  /** The root key the client trusts. */
  trustedRootPublicKey: Uint8Array;
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
  /** The real bytes/keys of this session, for the MITM exhibit to attack. */
  sessionMaterials: SessionMaterials;
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

  // The server's LONG-TERM identity — the same chain across sessions, so the
  // forward-secrecy contrast in the UI ("ephemeral keys vs the long-term
  // certificate key") describes something that is actually long-term.
  const chain = serverIdentity(serverName);

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
    sessionMaterials: {
      serverName,
      clientHello,
      clientKeys,
      serverPublicKey: serverKeys.publicKey,
      serverHello,
      encryptedExtensions,
      certificate,
      chain,
      certVerifyTranscript: thForCertVerify,
      certVerifySignature: certVerifySig,
      trustedRootPublicKey: chain.rootPublicKey,
    },
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

/** The three moves available to an attacker sitting between client and server. */
export type MitmAttack = 'reuse-cert' | 'own-key' | 'relay';

export const MITM_ATTACKS: { id: MitmAttack; label: string; premise: string }[] = [
  {
    id: 'reuse-cert',
    label: "Reuse the server's certificate",
    premise:
      "The attacker terminates the connection with its own key share, then replays the genuine, root-signed certificate it copied off the wire. It does not have the leaf private key, so it signs CertificateVerify with a key it does control.",
  },
  {
    id: 'own-key',
    label: 'Sign with its own key',
    premise:
      'The attacker mints its own root and leaf (anyone can be a CA), presents that chain, and signs CertificateVerify correctly with its own leaf private key.',
  },
  {
    id: 'relay',
    label: 'Relay unchanged',
    premise:
      "The attacker forwards the server's flight byte-for-byte and injects nothing. The client sees exactly the genuine conversation.",
  },
];

export interface MitmResult {
  attack: MitmAttack;
  label: string;
  premise: string;
  /** The client completed ECDHE with whatever peer it saw — always possible. */
  keyExchangeSucceeded: boolean;
  /** The chain the attacker presented, checked against the CLIENT's trust anchor. */
  chainVerdict: ChainVerdict;
  /** Subject on the leaf the client received, and its public key. */
  presentedLeafSubject: string;
  presentedLeafPublicKeyHex: string;
  /** Hash(ClientHello..Certificate) over the bytes the CLIENT actually received. */
  clientTranscriptHex: string;
  /** Hash(ClientHello..Certificate) of the genuine session (shown in section 2). */
  sessionTranscriptHex: string;
  transcriptsDiffer: boolean;
  /** Did the CertificateVerify the client received verify under the presented leaf key? */
  certificateVerifyAccepted: boolean;
  /** Would forwarding the server's genuine signature have satisfied this transcript? */
  replayedSignatureAccepted: boolean;
  /** Everything the client checks, ANDed. */
  clientAccepts: boolean;
  /** Does the attacker end up holding the same secret the client derived? */
  attackerHoldsSessionSecret: boolean;
  /** Safe iff the client refuses, or the attacker never gets the session secret. */
  attackBlocked: boolean;
  explanation: string[];
}

/**
 * Run one attacker strategy against THIS session's real material.
 *
 * The client's ClientHello, the genuine EncryptedExtensions, the genuine chain
 * and the genuine CertificateVerify signature all come from `materials`, so the
 * "real" transcript shown here is the same value section 2 displays after the
 * Certificate step — not a separate invention. Every verdict below is the
 * output of the same verifyChain / verifyCertificateVerify the honest handshake
 * runs, over the bytes each party actually saw.
 */
export async function runMitmAttempt(
  materials: SessionMaterials,
  attack: MitmAttack = 'reuse-cert',
): Promise<MitmResult> {
  const { clientHello, clientKeys, encryptedExtensions, chain, trustedRootPublicKey } = materials;
  const meta = MITM_ATTACKS.find((a) => a.id === attack) ?? MITM_ATTACKS[0];

  // The attacker holds two keys of two DIFFERENT types, because they do two
  // different jobs: an ephemeral X25519 keypair to complete key exchange, and an
  // Ed25519 keypair to sign with. (An earlier version passed the X25519 secret
  // to ed25519Sign; it only "worked" because both are 32 random bytes.)
  const attackerEphemeral = x25519Keygen();
  const attackerSigning = ed25519Keygen();
  const attackerRandom = randomBytes(32);

  // Relaying means the attacker changes nothing, so the client sees the genuine
  // ServerHello and the genuine server's key share. Every other move means the
  // attacker terminates the connection and substitutes its own.
  const relaying = attack === 'relay';
  const serverHelloSeen = relaying
    ? materials.serverHello
    : serializeServerHello(attackerRandom, attackerEphemeral.publicKey);
  const peerPublicKey = relaying ? materials.serverPublicKey : attackerEphemeral.publicKey;

  // Which certificate chain reaches the client.
  const presentedChain: CertChain = attack === 'own-key' ? issueChain(materials.serverName) : chain;
  const certificateSeen = relaying ? materials.certificate : serializeCertificate(presentedChain);

  // The transcript the CLIENT hashes is over the bytes the CLIENT received.
  const clientTranscript = await sha256(
    concatBytes(clientHello, serverHelloSeen, encryptedExtensions, certificateSeen),
  );

  // The CertificateVerify signature that reaches the client.
  let signatureSeen: Uint8Array;
  if (attack === 'own-key') {
    // Correctly signed — over the live transcript, with the attacker's own leaf key.
    signatureSeen = signCertificateVerify(clientTranscript, presentedChain.leafSecretKey);
  } else if (relaying) {
    signatureSeen = materials.certVerifySignature;
  } else {
    // Holds the genuine certificate, not its private key. Signs with what it has.
    signatureSeen = signCertificateVerify(clientTranscript, attackerSigning.secretKey);
  }

  // --- the client's checks, run for real -----------------------------------
  const chainVerdict = verifyChain(presentedChain, trustedRootPublicKey);
  const certificateVerifyAccepted = verifyCertificateVerify(
    clientTranscript,
    signatureSeen,
    presentedChain.leaf.publicKey,
  );
  // Could the attacker simply have forwarded the server's genuine signature?
  const replayedSignatureAccepted = verifyCertificateVerify(
    clientTranscript,
    materials.certVerifySignature,
    chain.leaf.publicKey,
  );
  const clientAccepts = chainVerdict.valid && certificateVerifyAccepted;

  // Key exchange always completes; the question is who ends up holding the key.
  const clientSecret = x25519SharedSecret(clientKeys.secretKey, peerPublicKey);
  const attackerSecret = x25519SharedSecret(attackerEphemeral.secretKey, clientKeys.publicKey);
  const keyExchangeSucceeded = clientSecret.length === 32;
  const attackerHoldsSessionSecret = equalBytes(clientSecret, attackerSecret);

  const transcriptsDiffer = !equalBytes(clientTranscript, materials.certVerifyTranscript);
  const attackBlocked = !clientAccepts || !attackerHoldsSessionSecret;

  const explanation: string[] = [
    meta.premise,
    `ECDHE completes either way — public keys are public. Here the attacker ${
      attackerHoldsSessionSecret
        ? 'does hold the same 32-byte secret the client derived, so key exchange alone would have handed it the session.'
        : 'does NOT hold the secret the client derived: it never injected a key share, so the client agreed its secret with the real server.'
    }`,
    `The transcript the client hashes ${
      transcriptsDiffer
        ? 'differs from the genuine session transcript, because the attacker changed bytes the hash covers.'
        : 'is byte-identical to the genuine session transcript, because nothing the hash covers was changed.'
    } Forwarding the server's real CertificateVerify would therefore ${
      replayedSignatureAccepted ? 'have satisfied this transcript.' : 'NOT have satisfied it.'
    }`,
    `Chain check against the client's trust anchor: ${
      chainVerdict.valid ? 'PASSES' : 'FAILS'
    } (anchor matches: ${chainVerdict.trustAnchorMatches}, root self-signature: ${
      chainVerdict.rootSelfSignatureValid
    }, leaf signed by root: ${chainVerdict.leafSignatureValid}).`,
    `CertificateVerify check against the presented leaf key: ${
      certificateVerifyAccepted ? 'PASSES' : 'FAILS'
    }.`,
    clientAccepts
      ? attackerHoldsSessionSecret
        ? 'The client accepts AND the attacker holds the session secret — this attack would succeed.'
        : 'The client accepts, but the attacker holds nothing: relaying without altering the handshake makes it a wire, not a listener. The moment it changes anything the hash covers, the checks above start failing.'
      : 'The client rejects the handshake, so the attacker never reaches the application data.',
  ];

  return {
    attack,
    label: meta.label,
    premise: meta.premise,
    keyExchangeSucceeded,
    chainVerdict,
    presentedLeafSubject: presentedChain.leaf.subject,
    presentedLeafPublicKeyHex: toHex(presentedChain.leaf.publicKey),
    clientTranscriptHex: toHex(clientTranscript),
    sessionTranscriptHex: toHex(materials.certVerifyTranscript),
    transcriptsDiffer,
    certificateVerifyAccepted,
    replayedSignatureAccepted,
    clientAccepts,
    attackerHoldsSessionSecret,
    attackBlocked,
    explanation,
  };
}

/** Exposed for tests: the exact CertificateVerify content the server signs. */
export const __testHooks = { certificateVerifyContent, AES128_KEY_BYTES, AEAD_IV_BYTES };
