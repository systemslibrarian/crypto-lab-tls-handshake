/**
 * Server authentication for the handshake: a tiny but *real* certificate chain
 * and the TLS 1.3 CertificateVerify signature.
 *
 * This is what stops a man-in-the-middle. The attacker can relay or replace the
 * ephemeral key share freely, but to impersonate the server it must produce a
 * CertificateVerify signature over the live transcript using the leaf's private
 * key — which it does not have. Authentication, not key exchange, is what binds
 * the session to the real server.
 *
 * We model a 2-link chain (root CA -> server leaf) with genuine Ed25519
 * signatures (RFC 8032), verified for real. A production X.509 chain carries far
 * more (validity periods, key usage, SANs, revocation); those are explicit
 * non-goals here — see crypto-lab-pki-chain for full certificate-path work.
 */
import {
  ED25519_PUB_BYTES,
  ED25519_SIG_BYTES,
  concatBytes,
  ed25519Keygen,
  ed25519Sign,
  ed25519Verify,
  utf8,
} from './primitives';

/** RFC 8446 §4.4.3 CertificateVerify context for a server signature. */
const CERT_VERIFY_CONTEXT = 'TLS 1.3, server CertificateVerify';
/** 64 octets of 0x20 (space) that prefix the signed content. */
const CERT_VERIFY_PADDING = new Uint8Array(64).fill(0x20);

export interface Certificate {
  subject: string;
  issuer: string;
  /** Ed25519 public key being certified (the leaf's signing key for the server). */
  publicKey: Uint8Array;
  /** Issuer's signature over (subject ‖ publicKey). */
  signature: Uint8Array;
}

export interface CertChain {
  root: Certificate;
  leaf: Certificate;
  /** The root's public key — a trust anchor the client already holds. */
  rootPublicKey: Uint8Array;
  /** The leaf's PRIVATE signing key. Never leaves the genuine server. */
  leafSecretKey: Uint8Array;
}

/** The bytes a CA signs to issue a certificate: subject identity ‖ certified key. */
function tbsCertificate(subject: string, publicKey: Uint8Array): Uint8Array {
  return concatBytes(utf8(subject), publicKey);
}

/**
 * Issue a fresh, self-contained chain for `serverName`. The root is self-signed
 * (a trust anchor); the leaf is signed by the root and carries the server's
 * ephemeral-per-session Ed25519 signing key.
 */
export function issueChain(serverName: string): CertChain {
  const rootKeys = ed25519Keygen();
  const leafKeys = ed25519Keygen();

  const rootSubject = 'Crypto Lab Root CA';
  const root: Certificate = {
    subject: rootSubject,
    issuer: rootSubject,
    publicKey: rootKeys.publicKey,
    signature: ed25519Sign(tbsCertificate(rootSubject, rootKeys.publicKey), rootKeys.secretKey),
  };

  const leaf: Certificate = {
    subject: serverName,
    issuer: rootSubject,
    publicKey: leafKeys.publicKey,
    signature: ed25519Sign(tbsCertificate(serverName, leafKeys.publicKey), rootKeys.secretKey),
  };

  return { root, leaf, rootPublicKey: rootKeys.publicKey, leafSecretKey: leafKeys.secretKey };
}

export interface ChainVerdict {
  rootSelfSignatureValid: boolean;
  leafSignatureValid: boolean;
  trustAnchorMatches: boolean;
  /** Overall: the chain validates only if every independent check passes. */
  valid: boolean;
}

/**
 * Validate the chain against a trust anchor. Each step is reported independently
 * (never collapsed into one boolean) so a failure points at *which* link broke.
 */
export function verifyChain(chain: CertChain, trustedRootPublicKey: Uint8Array): ChainVerdict {
  const trustAnchorMatches =
    chain.root.publicKey.length === ED25519_PUB_BYTES &&
    trustedRootPublicKey.length === ED25519_PUB_BYTES &&
    bytesEqual(chain.root.publicKey, trustedRootPublicKey);

  const rootSelfSignatureValid = ed25519Verify(
    chain.root.signature,
    tbsCertificate(chain.root.subject, chain.root.publicKey),
    chain.root.publicKey,
  );

  // The leaf must be signed BY THE ROOT — verified with the root's key.
  const leafSignatureValid = ed25519Verify(
    chain.leaf.signature,
    tbsCertificate(chain.leaf.subject, chain.leaf.publicKey),
    chain.root.publicKey,
  );

  return {
    trustAnchorMatches,
    rootSelfSignatureValid,
    leafSignatureValid,
    valid: trustAnchorMatches && rootSelfSignatureValid && leafSignatureValid,
  };
}

/** The exact content the server signs in CertificateVerify (RFC 8446 §4.4.3). */
export function certificateVerifyContent(transcriptHash: Uint8Array): Uint8Array {
  return concatBytes(CERT_VERIFY_PADDING, utf8(CERT_VERIFY_CONTEXT), new Uint8Array([0x00]), transcriptHash);
}

/** Server signs the transcript with the leaf private key, proving key possession. */
export function signCertificateVerify(transcriptHash: Uint8Array, leafSecretKey: Uint8Array): Uint8Array {
  const sig = ed25519Sign(certificateVerifyContent(transcriptHash), leafSecretKey);
  if (sig.length !== ED25519_SIG_BYTES) {
    throw new Error('CertificateVerify signature has wrong length');
  }
  return sig;
}

/** Client checks CertificateVerify against the public key in the leaf certificate. */
export function verifyCertificateVerify(
  transcriptHash: Uint8Array,
  signature: Uint8Array,
  leafPublicKey: Uint8Array,
): boolean {
  return ed25519Verify(signature, certificateVerifyContent(transcriptHash), leafPublicKey);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) {
    acc |= a[i] ^ b[i];
  }
  return acc === 0;
}
