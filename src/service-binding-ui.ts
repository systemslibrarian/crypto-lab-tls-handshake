import {
  ALPN_FAILURE_TEXT, BINDING_POLICIES, SERVICE_ROUTES, bindingOutcome, evaluateServiceBinding,
  type BindingHandshakeChecks, type BindingPolicy, type BindingResult, type ServiceRoute,
} from './service-binding';

function esc(value: string): string {
  return value.replace(/[&<>\"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;' })[c] ?? c);
}

function checkRow(id: string, label: string, matches: boolean, enforced: boolean, detail: string): string {
  const status = enforced ? (matches ? 'PASS' : 'FAIL') : 'NOT ENFORCED';
  return `<li class="binding-check" data-binding-check="${id}" data-matches="${matches}" data-enforced="${enforced}">
    <div><strong>${label}</strong><p>${esc(detail)}</p></div>
    <span class="binding-check-status ${enforced ? (matches ? 'yes' : 'no') : ''}">${status}</span>
  </li>`;
}

function evidence(route: ServiceRoute, policy: BindingPolicy, result: BindingResult): string {
  const names = (values: readonly string[]) => values.map((value) => `<code>${esc(value)}</code>`).join(', ');
  return `
    <div class="binding-facts">
      <div class="binding-fact"><h3>Client intent</h3><dl>
        <dt>Requested hostname / sent SNI</dt><dd><code>${esc(route.requestedName)}</code></dd>
        <dt>Intended protocol / ALPN offer</dt><dd><code>${esc(route.expectedProtocol)}</code> / ${names(route.offeredProtocols)}</dd>
      </dl></div>
      <div class="binding-fact"><h3>Routed endpoint · fixture</h3><dl>
        <dt>Recognized SNI names</dt><dd>${names(route.serverNames)}</dd>
        <dt>Certificate DNS names</dt><dd>${names(route.certificateNames)}</dd>
        <dt>Supported protocols</dt><dd>${names(route.supportedProtocols)}</dd>
        <dt>Claimed ALPN selection → actual handler</dt><dd><code>${esc(route.selectedProtocol ?? '(none)')}</code> → <code>${esc(route.handlerProtocol)}</code></dd>
      </dl></div>
    </div>
    <ol class="binding-checks" aria-label="Independent service admission checks">
      ${checkRow('handshake', 'Cryptographic handshake', result.handshakeAccepted, true,
        'Uses the current simulator’s real chain, CertificateVerify, both Finished checks, and shared-secret agreement. Try a fault in section 2.')}
      ${checkRow('certificate-name', 'Client checks certificate hostname', result.certificateNameMatches, true,
        result.certificateNameMatches ? 'The declared certificate names include the requested hostname. This says nothing about the application protocol.' : 'The declared certificate names do not include the requested hostname, even if SNI is recognized.')}
      ${checkRow('sni', 'Server checks the requested SNI name', result.sniRecognized, policy.enforceSni,
        result.sniRecognized ? 'Name recognized. Several protocols may still share this same hostname.' : 'Name not recognized. Strict SNI rejects it; this is separate from the client’s certificate-name check.')}
      ${checkRow('alpn', 'Application requires matched ALPN', result.alpnMatches, policy.requireAlpn,
        result.alpnFailure === null ? 'The selected protocol was offered, is supported, and matches both client intent and the receiving handler.' : ALPN_FAILURE_TEXT[result.alpnFailure])}
    </ol>
    ${result.blockedBy.length ? `<ul class="binding-reasons">${result.blockedBy.map((reason) => `<li>${esc(reason)}</li>`).join('')}</ul>` : ''}
    <p class="binding-lesson">${esc(route.lesson)}</p>`;
}

export function serviceBindingSection(route: ServiceRoute, policy: BindingPolicy, checks: BindingHandshakeChecks): string {
  const result = evaluateServiceBinding(route, policy, checks);
  return `<section class="panel" id="service-binding" aria-labelledby="binding-title">
    <h2 id="binding-title"><span class="section-num">8</span> A Valid Handshake — For Which Service?</h2>
    <p class="lead">A trusted certificate can cover several services. Route an HTTP client to a different endpoint,
      then compare the name and application-protocol checks. Start with the same hostname: does adding SNI stop a mail service?</p>
    <div class="binding-controls">
      <label for="bindingRoute">Service route
        <select id="bindingRoute">${SERVICE_ROUTES.map((choice) => `<option value="${choice.id}" ${choice.id === route.id ? 'selected' : ''}>${esc(choice.label)}</option>`).join('')}</select>
      </label>
      <label for="bindingPolicy">Admission policy
        <select id="bindingPolicy">${BINDING_POLICIES.map((choice) => `<option value="${choice.id}" ${choice.id === policy.id ? 'selected' : ''}>${esc(choice.label)}</option>`).join('')}</select>
      </label>
    </div>
    <p id="bindingOutcome" class="binding-outcome" role="status" aria-live="polite" aria-atomic="true"
      data-admitted="${result.admitted}" data-intended="${result.intendedService}">${esc(bindingOutcome(result, policy))}</p>
    <div id="bindingEvidence">${evidence(route, policy, result)}</div>
    <p class="lead binding-scope"><strong>Bounded service-routing model.</strong> DNS names, services, and ALPN values are synthetic fixtures,
      separate from the cryptographic transcript above. There is no network TLS negotiation, X.509/SAN parser, HTTP/SMTP parser,
      or real ALPACA exploit here. The incomplete policies deliberately omit checks. A wrong-service admission shows a missing binding,
      not that an application exploit or data theft has occurred.</p>
    <p class="lead">SNI is a server-side routing/name policy; certificate hostname validation is a client identity check.
      ALPN binds the selected application protocol, and the application must honor that selection. In TLS 1.3 the server’s ALPN
      response belongs in EncryptedExtensions; this panel adds no extensions to the simulator’s handshake bytes.</p>
    <p class="lead binding-sources">Sources:
      <a href="https://www.usenix.org/conference/usenixsecurity21/presentation/brinkmann">ALPACA, USENIX Security 2021</a>;
      <a href="https://www.rfc-editor.org/rfc/rfc9325.html#section-3.7">RFC 9325 §§3.7–3.9</a>;
      <a href="https://www.rfc-editor.org/rfc/rfc7301.html#section-3.2">RFC 7301 §3.2</a>;
      <a href="https://www.rfc-editor.org/info/rfc9846/">RFC 9846 §4.3 (extension locations)</a>.</p>
  </section>`;
}

/** Keep controls and the live region mounted so keyboard focus and announcements survive a change. */
export function updateServiceBinding(route: ServiceRoute, policy: BindingPolicy, checks: BindingHandshakeChecks): void {
  const result = evaluateServiceBinding(route, policy, checks);
  const output = document.querySelector<HTMLElement>('#bindingOutcome');
  const body = document.querySelector<HTMLElement>('#bindingEvidence');
  if (!output || !body) return;
  output.textContent = bindingOutcome(result, policy);
  output.dataset.admitted = String(result.admitted);
  output.dataset.intended = String(result.intendedService);
  body.innerHTML = evidence(route, policy, result);
}
