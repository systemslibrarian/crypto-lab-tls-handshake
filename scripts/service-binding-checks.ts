import {
  BINDING_POLICIES, SERVICE_ROUTES, evaluateServiceBinding,
  type BindingHandshakeChecks,
} from '../src/service-binding';

/** Expected outcomes specified independently of the model's decision code. */
export function checkServiceBinding(assert: (condition: boolean, message: string) => void): void {
  const honest: BindingHandshakeChecks = {
    chainValid: true, certificateVerifyValid: true, serverFinishedValid: true,
    clientFinishedValid: true, sharedSecretAgrees: true,
  };
  const expectations: Record<string, readonly boolean[]> = {
    // certificate only, +SNI, +ALPN, +both
    'intended-web': [true, true, true, true],
    'other-name-mail': [true, false, false, false],
    'same-name-mail': [true, true, false, false],
    'other-name-web': [true, false, true, false],
    'wrong-certificate': [false, false, false, false],
    'missing-alpn': [true, true, false, false],
    'unoffered-alpn': [true, true, false, false],
    'wrong-handler': [true, true, false, false],
  };
  assert(BINDING_POLICIES.map((p) => p.id).join(',') === 'certificate,sni,alpn,sni-alpn', 'binding policy matrix order changed');
  assert(SERVICE_ROUTES.length === Object.keys(expectations).length, 'every route needs an independent expected outcome');
  for (const route of SERVICE_ROUTES) {
    assert(route.id in expectations, `missing outcome for ${route.id}`);
    for (const [index, policy] of BINDING_POLICIES.entries()) {
      const result = evaluateServiceBinding(route, policy, honest);
      assert(result.admitted === expectations[route.id][index], `${route.id}/${policy.id}: incorrect admission`);
    }
  }
  const web = SERVICE_ROUTES.find((route) => route.id === 'intended-web')!;
  const sameNameMail = SERVICE_ROUTES.find((route) => route.id === 'same-name-mail')!;
  const strict = BINDING_POLICIES.find((policy) => policy.id === 'sni-alpn')!;
  const sniOnly = BINDING_POLICIES.find((policy) => policy.id === 'sni')!;
  const confused = evaluateServiceBinding(sameNameMail, sniOnly, honest);
  assert(confused.handshakeAccepted && confused.certificateNameMatches && confused.sniRecognized,
    'same-host cross-protocol control must pass the cryptographic and name checks');
  assert(confused.admitted && !confused.intendedService && !confused.alpnMatches,
    'SNI alone must admit the wrong protocol in the declared same-host fixture');
  assert(evaluateServiceBinding(sameNameMail, strict, honest).alpnFailure === 'no-common-protocol',
    'strict ALPN must reject disjoint protocol lists');

  for (const check of Object.keys(honest) as (keyof BindingHandshakeChecks)[]) {
    for (const policy of BINDING_POLICIES) {
      const rejected = evaluateServiceBinding(web, policy, { ...honest, [check]: false });
      assert(!rejected.admitted && !rejected.handshakeAccepted, `${check} failure must block ${policy.id}`);
      assert(rejected.certificateNameMatches && rejected.sniRecognized && rejected.alpnMatches,
        `${check} failure must not alter the independent name/protocol observations`);
    }
  }
  const wrongCertificate = SERVICE_ROUTES.find((route) => route.id === 'wrong-certificate')!;
  const nameFailure = evaluateServiceBinding(wrongCertificate, strict, honest);
  assert(nameFailure.sniRecognized && nameFailure.alpnMatches && !nameFailure.certificateNameMatches,
    'recognized SNI and matching ALPN must not substitute for certificate hostname validation');

  const missingAlpn = SERVICE_ROUTES.find((route) => route.id === 'missing-alpn')!;
  assert(evaluateServiceBinding(missingAlpn, strict, honest).alpnFailure === 'missing-selection',
    'missing ALPN with available overlap must remain distinct from disjoint protocols');
  const unoffered = SERVICE_ROUTES.find((route) => route.id === 'unoffered-alpn')!;
  assert(evaluateServiceBinding(unoffered, strict, honest).alpnFailure === 'unoffered-selection',
    'a server must not choose an unoffered protocol');
  const wrongHandler = SERVICE_ROUTES.find((route) => route.id === 'wrong-handler')!;
  assert(evaluateServiceBinding(wrongHandler, strict, honest).alpnFailure === 'wrong-handler',
    'the application must use the selected ALPN protocol');
  assert(evaluateServiceBinding({ ...web, supportedProtocols: ['smtp'] }, strict, honest).alpnFailure === 'unsupported-selection',
    'a claimed selection must also be supported by the endpoint');
  assert(evaluateServiceBinding({
    ...web, offeredProtocols: ['http/1.1', 'smtp'], supportedProtocols: ['smtp'], selectedProtocol: 'smtp', handlerProtocol: 'smtp',
  }, strict, honest).alpnFailure === 'unexpected-protocol', 'an offered alternative must still satisfy this application’s declared intent');
  assert(evaluateServiceBinding({ ...web, selectedProtocol: 'HTTP/1.1' }, strict, honest).alpnFailure === 'unoffered-selection',
    'ALPN identifiers are exact opaque strings, not case-insensitive DNS names');
  assert(evaluateServiceBinding({ ...web, requestedName: 'ACCOUNTS.EXAMPLE.TEST' }, strict, honest).admitted,
    'ASCII DNS-name fixtures must compare case-insensitively');
  console.log('service binding: 32 route/policy outcomes, every handshake failure, and name/ALPN boundaries: PASS');
}
