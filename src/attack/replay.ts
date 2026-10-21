/**
 * A passive recorder's entire 0-RTT capability: copy bytes from the wire and
 * send the same bytes again. No PSK, ticket key, endpoint key, or parser enters
 * this module.
 */
import type { RecordedEarlyFlight } from '../antireplay';

export function recordEarlyFlight(flight: RecordedEarlyFlight): RecordedEarlyFlight {
  return {
    clientHello: Uint8Array.from(flight.clientHello),
    earlyDataRecord: Uint8Array.from(flight.earlyDataRecord),
  };
}

export function replayEarlyFlight(recording: RecordedEarlyFlight): RecordedEarlyFlight {
  return {
    clientHello: Uint8Array.from(recording.clientHello),
    earlyDataRecord: Uint8Array.from(recording.earlyDataRecord),
  };
}
