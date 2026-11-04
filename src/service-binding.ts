/**
 * A bounded service-admission model, not a TLS encoder or a network exploit.
 * Names and ALPN values are declared fixtures; only the supplied cryptographic
 * checks come from the live handshake. Exact ASCII DNS names only: no X.509,
 * wildcard, IDNA, DNS resolution, port authentication, or application parser.
 */
export interface BindingHandshakeChecks {
  chainValid: boolean;
  certificateVerifyValid: boolean;
  serverFinishedValid: boolean;
  clientFinishedValid: boolean;
  sharedSecretAgrees: boolean;
}

export interface ServiceRoute {
  id: string;
  label: string;
  lesson: string;
  requestedName: string;
  expectedProtocol: string;
  offeredProtocols: readonly string[];
  serverNames: readonly string[];
  certificateNames: readonly string[];
  supportedProtocols: readonly string[];
  selectedProtocol: string | null;
  handlerProtocol: string;
}

export interface BindingPolicy {
  id: string;
  label: string;
  enforceSni: boolean;
  requireAlpn: boolean;
}

export const BINDING_POLICIES: readonly BindingPolicy[] = [
  { id: 'certificate', label: 'Certificate checks only', enforceSni: false, requireAlpn: false },
  { id: 'sni', label: 'Add strict SNI', enforceSni: true, requireAlpn: false },
  { id: 'alpn', label: 'Add strict ALPN', enforceSni: false, requireAlpn: true },
  { id: 'sni-alpn', label: 'Require SNI + ALPN', enforceSni: true, requireAlpn: true },
];

const WEB = 'accounts.example.test';
const MAIL = 'mail.example.test';
const HTTP = 'http/1.1';
const webRoute = {
  requestedName: WEB,
  expectedProtocol: HTTP,
  offeredProtocols: [HTTP],
  serverNames: [WEB],
  certificateNames: [WEB, MAIL],
  supportedProtocols: [HTTP],
  selectedProtocol: HTTP,
  handlerProtocol: HTTP,
};

export const SERVICE_ROUTES: readonly ServiceRoute[] = [
  {
    ...webRoute, id: 'intended-web', label: 'Intended web service',
    lesson: 'The requested name, certificate name, selected protocol, and application handler all agree.',
  },
  {
    ...webRoute, id: 'other-name-mail', label: 'Other hostname, mail service',
    serverNames: [MAIL], supportedProtocols: ['smtp'], selectedProtocol: null, handlerProtocol: 'smtp',
    lesson: 'The fixture certificate covers both hostnames. It still names the requested host, but this mail service does not recognize that SNI name and cannot select the offered HTTP protocol.',
  },
  {
    ...webRoute, id: 'same-name-mail', label: 'Same hostname, mail service',
    supportedProtocols: ['smtp'], selectedProtocol: null, handlerProtocol: 'smtp',
    lesson: 'SNI alone cannot separate two services on the same hostname. The mail service recognizes the name, but its protocol is not the HTTP protocol the client offered.',
  },
  {
    ...webRoute, id: 'other-name-web', label: 'Other hostname, web service',
    serverNames: [MAIL],
    lesson: 'ALPN alone cannot distinguish two hostnames serving the same protocol. The certificate covers both names, so strict server-side name policy supplies the missing check.',
  },
  {
    ...webRoute, id: 'wrong-certificate', label: 'Certificate names another host',
    certificateNames: [MAIL],
    lesson: 'Recognizing SNI is not certificate hostname validation. The client must reject this certificate-name fixture even though the server accepts the requested name and protocol.',
  },
  {
    ...webRoute, id: 'missing-alpn', label: 'Web service omits ALPN', selectedProtocol: null,
    lesson: 'A missing ALPN selection is not a protocol match. This exercise’s strict application policy requires a selection; it does not claim that every TLS application universally requires ALPN.',
  },
  {
    ...webRoute, id: 'unoffered-alpn', label: 'Server selects unoffered protocol',
    supportedProtocols: ['smtp'], selectedProtocol: 'smtp', handlerProtocol: 'smtp',
    lesson: 'The server claims a protocol the client did not offer. Strict ALPN rejects it. Accepting this claim under an incomplete policy is a failure demonstration, not compliant negotiation.',
  },
  {
    ...webRoute, id: 'wrong-handler', label: 'HTTP selected, mail handler used',
    supportedProtocols: [HTTP, 'smtp'], handlerProtocol: 'smtp',
    lesson: 'The application must honor the selected ALPN protocol. Selecting HTTP and then delivering its data to an SMTP handler breaks the binding even when negotiation appears to match.',
  },
];

export type AlpnFailure = 'no-common-protocol' | 'missing-selection' | 'unoffered-selection'
  | 'unsupported-selection' | 'unexpected-protocol' | 'wrong-handler';

export const ALPN_FAILURE_TEXT: Record<AlpnFailure, string> = {
  'no-common-protocol': 'No protocol overlap: a strict server rejects with no_application_protocol.',
  'missing-selection': 'No ALPN selection: this application’s required-protocol policy rejects it.',
  'unoffered-selection': 'The selected protocol was not offered by the client.',
  'unsupported-selection': 'The selected protocol is not supported by this endpoint.',
  'unexpected-protocol': 'The selected protocol is not the application protocol this client intends.',
  'wrong-handler': 'The selected protocol and the receiving application handler differ.',
};

export interface BindingResult {
  handshakeAccepted: boolean;
  certificateNameMatches: boolean;
  sniRecognized: boolean;
  alpnFailure: AlpnFailure | null;
  alpnMatches: boolean;
  admitted: boolean;
  intendedService: boolean;
  blockedBy: readonly string[];
}

function sameFixtureName(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

export function evaluateServiceBinding(
  route: ServiceRoute,
  policy: BindingPolicy,
  checks: BindingHandshakeChecks,
): BindingResult {
  const handshakeAccepted = checks.chainValid && checks.certificateVerifyValid
    && checks.serverFinishedValid && checks.clientFinishedValid && checks.sharedSecretAgrees;
  const certificateNameMatches = route.certificateNames.some((name) => sameFixtureName(name, route.requestedName));
  const sniRecognized = route.serverNames.some((name) => sameFixtureName(name, route.requestedName));
  const selected = route.selectedProtocol;
  let alpnFailure: AlpnFailure | null = null;
  if (selected === null) {
    alpnFailure = route.supportedProtocols.some((protocol) => route.offeredProtocols.includes(protocol))
      ? 'missing-selection' : 'no-common-protocol';
  } else if (!route.offeredProtocols.includes(selected)) {
    alpnFailure = 'unoffered-selection';
  } else if (!route.supportedProtocols.includes(selected)) {
    alpnFailure = 'unsupported-selection';
  } else if (selected !== route.expectedProtocol) {
    alpnFailure = 'unexpected-protocol';
  } else if (selected !== route.handlerProtocol) {
    alpnFailure = 'wrong-handler';
  }
  const alpnMatches = alpnFailure === null;
  const blockedBy: string[] = [];
  if (!handshakeAccepted) blockedBy.push('Current cryptographic handshake failed.');
  if (!certificateNameMatches) blockedBy.push('The certificate fixture does not name the requested host.');
  if (policy.enforceSni && !sniRecognized) blockedBy.push('The server rejects an unrecognized SNI name.');
  if (policy.requireAlpn && alpnFailure !== null) blockedBy.push(ALPN_FAILURE_TEXT[alpnFailure]);
  return {
    handshakeAccepted, certificateNameMatches, sniRecognized, alpnFailure, alpnMatches,
    admitted: blockedBy.length === 0,
    intendedService: sniRecognized && route.handlerProtocol === route.expectedProtocol,
    blockedBy,
  };
}

export function bindingOutcome(result: BindingResult, policy: BindingPolicy): string {
  if (!result.admitted) return 'Blocked before application delivery.';
  if (!result.intendedService) return 'Wrong service admitted by this incomplete policy.';
  if (!policy.enforceSni || !policy.requireAlpn) return 'Intended service reached; some service checks are not enforced.';
  return 'Intended service admitted with name and protocol checks.';
}
