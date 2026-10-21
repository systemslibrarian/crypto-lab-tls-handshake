/**
 * DELIBERATELY WEAK TLS mode, NEVER THE DEFAULT.
 *
 * RFC 9846 psk_ke mixes no asymmetric shared secret into the Handshake Secret.
 * Hash.length zero bytes take its place. Keeping that choice here makes the
 * missing-forward-secrecy branch explicit and auditable.
 */
export function pskOnlyAsymmetricInput(hashLength: number): Uint8Array {
  return new Uint8Array(hashLength);
}
