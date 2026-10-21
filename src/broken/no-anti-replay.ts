/**
 * DELIBERATELY BROKEN, NEVER THE DEFAULT.
 *
 * This policy authenticates and decrypts 0-RTT but keeps no replay state. It is
 * isolated so the unsafe acceptance rule cannot be mistaken for the ordinary
 * server path.
 */
export function acceptWithoutReplayProtection(): true {
  return true;
}
