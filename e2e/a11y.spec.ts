import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the TLS 1.3 Handshake lab.
 *
 * The app is a single page rendered by main.ts (no tabs, no <details>). It has
 * an interactive simulator (Step/Back/Auto-play/New-session), a per-message
 * ladder, and a MITM "attack" button that injects a result region only after
 * it's clicked. So we drive the simulator to the LAST step (so every message
 * row + its detail card, including the app-key/handshake-key states, is
 * rendered), and fire the MITM button so its injected verdicts/box are in the
 * DOM. Then we neutralize motion/opacity (the ladder dims un-reached rows via
 * opacity, and the shell fades in) so the contrast checker sees final states.
 *
 * Scans both themes with WCAG 2.0/2.1 A + AA; asserts zero violations.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight states (shell fade-in,
// dimmed ladder rows) can't hide text from the contrast checker.
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
      opacity:1!important;scroll-behavior:auto!important;
    }`,
  });
}

// Generic collapsible reveal for robustness (this lab has none today).
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

// Drive the simulator to the last step and trigger the MITM attack so all the
// dynamically-injected regions (detail cards for every flight, MITM verdict
// box) exist and are painted when axe runs.
async function driveDemo(page: Page): Promise<void> {
  // Step through the whole handshake so each message's detail card renders.
  const next = page.locator('#nextBtn');
  for (let i = 0; i < 12; i++) {
    if (await next.isDisabled().catch(() => false)) break;
    await next.click();
  }
  // Fire the MITM attack to inject its blocked/verdicts region.
  await page.locator('#mitmBtn').click();
  await expect(page.locator('.mitm-box')).toBeVisible();
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  // App is rendered by main.ts after an async handshake; wait for the shell.
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('.shell')).toBeVisible();
  await expect(page.locator('#nextBtn')).toBeVisible();
});

test('no WCAG A/AA violations in dark theme (simulator driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemo(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme (simulator driven)', async ({ page }) => {
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemo(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});
