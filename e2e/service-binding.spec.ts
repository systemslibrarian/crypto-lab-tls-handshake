import { expect, test, type Page } from '@playwright/test';
import { boot, NARROW, scan } from './gate';

async function select(page: Page, route: string, policy: string): Promise<void> {
  await page.locator('#bindingRoute').selectOption(route);
  await page.locator('#bindingPolicy').selectOption(policy);
}

test('service binding: the route/policy matrix exposes the two independent bindings', async ({ page }) => {
  await boot(page, 'dark');
  // Literal expected results, not calculated by the production evaluator.
  const policies = ['certificate', 'sni', 'alpn', 'sni-alpn'];
  const matrix: Record<string, boolean[]> = {
    'intended-web': [true, true, true, true],
    'other-name-mail': [true, false, false, false],
    'same-name-mail': [true, true, false, false],
    'other-name-web': [true, false, true, false],
    'wrong-certificate': [false, false, false, false],
    'missing-alpn': [true, true, false, false],
    'unoffered-alpn': [true, true, false, false],
    'wrong-handler': [true, true, false, false],
  };
  for (const [route, outcomes] of Object.entries(matrix)) {
    for (const [index, policy] of policies.entries()) {
      await select(page, route, policy);
      await expect(page.locator('#bindingOutcome'), `${route}/${policy}`).toHaveAttribute('data-admitted', String(outcomes[index]));
      await expect(page.locator('#bindingOutcome')).toHaveText(outcomes[index] ? /admitted|reached/ : 'Blocked before application delivery.');
    }
  }
  await select(page, 'same-name-mail', 'sni');
  await expect(page.locator('[data-binding-check="sni"]')).toHaveAttribute('data-matches', 'true');
  await expect(page.locator('[data-binding-check="certificate-name"]')).toHaveAttribute('data-matches', 'true');
  await expect(page.locator('[data-binding-check="alpn"]')).toHaveAttribute('data-matches', 'false');
  await expect(page.locator('#bindingOutcome')).toHaveText('Wrong service admitted by this incomplete policy.');
  await expect(page.locator('#bindingOutcome')).toHaveAttribute('data-intended', 'false');
  await page.locator('#bindingPolicy').selectOption('sni-alpn');
  await expect(page.locator('.binding-reasons')).toContainText('no_application_protocol');
  await expect(page.locator('#bindingOutcome')).toHaveAttribute('data-admitted', 'false');

  await select(page, 'wrong-certificate', 'sni-alpn');
  await expect(page.locator('[data-binding-check="sni"]')).toHaveAttribute('data-matches', 'true');
  await expect(page.locator('[data-binding-check="certificate-name"]')).toHaveAttribute('data-matches', 'false');
  await expect(page.locator('.binding-reasons')).toContainText('certificate fixture does not name');
});

test('service binding: current handshake failures block every route without inventing a name or ALPN failure', async ({ page }) => {
  await boot(page, 'dark');
  await select(page, 'intended-web', 'sni-alpn');
  for (const fault of ['ecdhe', 'transcript']) {
    await page.locator(`[data-fault="${fault}"]`).click();
    await expect(page.locator('[data-binding-check="handshake"]')).toHaveAttribute('data-matches', 'false');
    await expect(page.locator('#bindingOutcome')).toHaveAttribute('data-admitted', 'false');
    await expect(page.locator('.binding-reasons')).toHaveText('Current cryptographic handshake failed.');
    for (const check of ['certificate-name', 'sni', 'alpn']) {
      await expect(page.locator(`[data-binding-check="${check}"]`)).toHaveAttribute('data-matches', 'true');
    }
  }
  await page.locator('[data-fault="none"]').click();
  await expect(page.locator('#bindingOutcome')).toHaveAttribute('data-admitted', 'true');
  await expect(page.locator('#bindingRoute')).toHaveValue('intended-web');
  await expect(page.locator('#bindingPolicy')).toHaveValue('sni-alpn');
});

test('service binding: keyboard changes retain focus and do not step the handshake', async ({ page }) => {
  await boot(page, 'dark');
  const control = page.getByLabel('Admission policy', { exact: true });
  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'true');
  await control.focus();
  await control.selectOption('sni-alpn');
  await expect(control).toBeFocused();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#bindingOutcome')).toHaveAttribute('role', 'status');
  const stoppedStep = await page.locator('.progress').innerText();
  await control.press('ArrowRight');
  await expect(page.locator('.progress')).toHaveText(stoppedStep);
  await expect(control).toBeFocused();
  await expect(page.locator('#service-binding')).toContainText('no network TLS negotiation');
  await expect(page.locator('#service-binding')).toContainText('not that an application exploit or data theft has occurred');
});

for (const narrow of [false, true]) {
  test(`service binding: reachable checks and verdicts pass the accessibility gate${narrow ? ' at 320px' : ''}`, async ({ page }) => {
    test.setTimeout(300_000);
    if (narrow) await page.setViewportSize(NARROW);
    await boot(page, 'dark');
    // Drive warning, strict rejection, positive control, and certificate failure.
    // Other ALPN failures share these styles and are covered by the matrix.
    for (const [route, policy] of [
      ['same-name-mail', 'sni'], ['same-name-mail', 'sni-alpn'],
      ['intended-web', 'sni-alpn'], ['wrong-certificate', 'sni-alpn'],
    ]) {
      await select(page, route, policy);
      await expect(page.locator('.binding-check')).toHaveCount(4);
      await expect(page.locator('#bindingOutcome')).toBeVisible();
      await scan(page, `service binding ${route}/${policy}${narrow ? ' at 320px' : ''}`);
    }
  });
}
