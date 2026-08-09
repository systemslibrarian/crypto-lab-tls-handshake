import { test } from '@playwright/test';
import { boot, driveAllStates, NARROW } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along the handshake it teaches: the skip link focused, all
 * eight messages stepped through so every detail card, every lock badge and
 * every mix of unreached / seen / current ladder rows is painted, a step
 * reached again by Back and by a direct ladder jump, auto-play toggled both
 * ways, the HKDF derivation `<details>` opened through its summary, all three
 * fault choices injected and their real verifier verdicts scanned, all three
 * MITM moves run — including `relay`, the one the client accepts — and a new
 * session started. Every one of those states is scanned, in both themes, at
 * desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why each scan
 * asserts its content first, and why `violations` is not the whole oracle.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    await boot(page, theme);
    await driveAllStates(page, theme);
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
  });
}
