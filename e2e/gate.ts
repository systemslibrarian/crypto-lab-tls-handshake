import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/** The handshake this lab walks: eight messages, ClientHello to Application Data. */
export const STEP_COUNT = 8;

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaced
 *     pushed `*{opacity:1!important}` through `addStyleTag` before every scan.
 *     In this lab that was not a rounding error, it was the whole result: the
 *     message ladder dims every not-yet-reached row to `opacity: .45`, so at
 *     any given step most of the ladder is faded — and the injected override
 *     handed axe eleven rows' worth of foreground colours the browser never
 *     paints. A green contrast gate here meant nothing at all.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over an empty container passes having checked
 *     nothing. At first paint this page shows step 1 of 8: the detail card has
 *     no transcript-binding note and no encrypted lock badge, because
 *     ClientHello binds nothing and travels in the clear; the MITM panel is a
 *     chooser with no verdict box; the fault panel is in its honest state with
 *     four passing pills and no failing ones; and the HKDF "show your work"
 *     `<details>` is closed. Every failing pill, every
 *     `mc-bad` cell, the dashed faulted panel, the ⚠ ATTACK SUCCEEDED box and
 *     the whole derivation view exist only after those states are driven.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. `.shell`
 * runs `fade-in` from `opacity: 0` and is exactly that shape; it is safe only
 * because the reduced-motion block collapses the duration to 0.01ms rather than
 * setting `animation: none`, so the keyframe still lands on its end state.
 *
 * `aria-hidden` subtrees are excluded, and that exclusion is doing real work
 * here rather than being defensive: `.packet` — the token that flies along the
 * wire when you press Step — is declared `opacity: 0` and is only ever visible
 * inside its own keyframe, which reduced motion skips entirely (`animatePacket`
 * returns early and flashes the receiving lane instead). It carries the message
 * title as text, so without this it would be reported in every state. It is
 * `aria-hidden` precisely because it is a decoration duplicating the row label
 * beside it, and the cost of the exclusion is stated plainly: text removed from
 * the accessibility tree AND painted at zero opacity is not checked here.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. That assertion is load-bearing here:
 * `main.ts` reads `matchMedia('(prefers-reduced-motion: reduce)')` once at
 * module evaluation and branches the packet animation on it forever after, so
 * an emulation that silently did nothing would leave the gate driving a
 * different app than the one it claims to certify.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is rendered by main.ts after a real async handshake.
  await expect(page.locator('.shell')).toBeVisible();
  await expect(page.locator('.msg')).toHaveCount(STEP_COUNT);
  await expect(page.locator('.progress')).toHaveText(`Step 1 / ${STEP_COUNT}`);
  // The regions that carry the lab's claims do not exist here, which is the
  // whole reason `driveAllStates` exists.
  await expect(page.locator('.mitm-box')).toHaveCount(0);
  await expect(page.locator('.fault-panel.faulted')).toHaveCount(0);
  await expect(page.locator('.deriv')).not.toHaveAttribute('open', '');
  // ClientHello binds no transcript (nothing precedes it) and travels in the
  // clear, so the binding note and both encrypted lock badges are absent from
  // the detail card here.
  await expect(page.locator('.detail .tx-bind')).toHaveCount(0);
  await expect(page.locator('.detail .lock.plaintext')).toHaveCount(1);
  await expect(page.locator('.detail .lock.handshake')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 32-byte hex dumps as 32 individual `.byte`
 * cells, lays the simulator on a two-column grid with an eight-row ladder in
 * one half, and puts three `.pillars` and three `.scope-cards` on
 * three-column grids. `.panel` and the simulator's children carry `min-width:
 * 0` precisely so this assertion holds.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has the same decoy: the
    // four `.codebox` record fields are `white-space: pre` inside their own
    // `overflow-x: auto`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Assert a revealed element is wholly on screen and wholly unclipped.
 *
 * Neither axe nor the contrast oracle has anything to say about this, and both
 * are content to measure a box whose right-hand third is not painted. This lab
 * has no popovers, so the oracle is pointed at the three blocks that only exist
 * after driving and that each carry a verdict a reader has to be able to read
 * in full: the MITM box, the HKDF output card inside the `<details>`, and the
 * transcript chip in the simulator's detail card. All three sit several boxes
 * deep next to deliberate `overflow-x: auto` scrollers, so an `overflow` added
 * one level up would cut them without failing any other assertion here.
 */
export async function expectNotClipped(
  page: Page,
  selector: string,
  label: string
): Promise<void> {
  // Measure the settled frame, the same one `scan` measures.
  await settle(page);
  const cut = await page.evaluate((sel) => {
    const el = document.querySelector(sel);
    if (!el) return `no element matched ${sel}`;
    const b = el.getBoundingClientRect();
    if (b.width <= 0 || b.height <= 0) return `${sel} has an empty box`;
    const out: string[] = [];
    if (b.left < -0.5 || b.right > window.innerWidth + 0.5) {
      out.push(`outside the viewport (${Math.round(b.left)}..${Math.round(b.right)} of ${window.innerWidth})`);
    }
    for (let n = el.parentElement; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (!/auto|scroll|hidden|clip/.test(cs.overflowX + ' ' + cs.overflowY)) continue;
      const c = n.getBoundingClientRect();
      const lost = Math.max(0, c.left - b.left) + Math.max(0, b.right - c.right) +
        Math.max(0, c.top - b.top) + Math.max(0, b.bottom - c.bottom);
      if (lost > 0.5) {
        out.push(
          `${Math.round(lost)}px clipped by ${n.tagName.toLowerCase()}` +
            `${n.id ? '#' + n.id : ''}.${(n.getAttribute('class') ?? '').trim()}`
        );
      }
    }
    return out.length ? out.join('; ') : null;
  }, selector);
  expect(cut, `${selector} must be fully painted in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    almost every tinted surface is a `color-mix()` axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish — including `aria-prohibited-attr`, which is where an `aria-label`
 *    on a role-less div hides, a defect that never reaches the violations array
 *    at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * Measure the 500ms arrival flash, which a full scan cannot catch reliably.
 *
 * Under reduced motion the packet does not fly; `animatePacket` instead adds
 * `.flash` to the receiving lane head and removes it 500ms later. That is a real
 * state — for a reader with the preference set it is the ONLY arrival feedback —
 * but 500ms is shorter than a full axe pass, so a `scan` would measure it only
 * sometimes, and a sometimes-measured assertion is worse than none.
 *
 * So it is measured with the same composite-aware oracle, scoped to
 * `.lane-heads *`, which takes a couple of milliseconds. The class is confirmed
 * present BEFORE and AFTER the measurement, so a run where the flash had already
 * expired fails loudly instead of passing on an empty check.
 */
export async function expectFlashLegible(page: Page, label: string): Promise<void> {
  // Measure a settled frame. `render()` re-creates `.shell` on every step, which
  // restarts its `fade-in` keyframe; reduced motion collapses that to 0.01ms but
  // the very first frame after the click can still be caught at `opacity: 0`,
  // where every colour on the page composites to the same backdrop and the
  // oracle reports a meaningless 1:1. Settling costs ~100ms of the flash's 500.
  await settle(page);
  const flash = page.locator('.lane-heads .flash');
  await expect(flash, `the arrival flash must be painted to be measured: ${label}`).toHaveCount(1);
  const failures = Array.from(
    new Set(formatContrastFailures(await auditContrast(page, '.lane-heads *')))
  );
  expect(
    await flash.count(),
    `the arrival flash expired before the measurement landed: ${label}`
  ).toBe(1);
  expect(failures, `arrival-flash lane heads in state: ${label}`).toEqual([]);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * There are four independent controls and one prerequisite between them: the
 * MITM panel attacks THIS session's material, and choosing a fault re-runs the
 * whole handshake and clears any MITM result (`state.mitm = null` in the fault
 * handler), so the faults have to be driven before the attacks or the attack
 * verdicts are thrown away unscanned.
 *
 * The drive covers:
 *
 *   - all eight ladder steps, because the detail card is different at every
 *     one: the "Keys & secrets derived" block does not exist until ServerHello,
 *     the transcript-binding note only appears on the two messages that sign or
 *     MAC it, and the 🔒 handshake-key and 🔒 app-key lock badges are three
 *     different palettes that appear at three different points. Stepping also
 *     walks the ladder through every mix of unreached / seen / current rows;
 *   - the HKDF `<details>`, opened through its `<summary>`, which is the only
 *     route to the derivation equation, the two length bars and the output card;
 *   - all three fault choices, because the honest panel paints four passing
 *     pills and the two faulted ones paint mixtures — the ECDHE fault is the
 *     only state on the page with passing and failing pills side by side inside
 *     the dashed `.faulted` background;
 *   - all three MITM moves. Each paints a different mixture of `mc-good` and
 *     `mc-neutral` cells and a different transcript comparison — `relay` is the
 *     only one whose two hashes are identical and whose `good-tag` is used
 *     twice, the other two paint the `bad-tag`;
 *   - a new session, which returns to step 1 with fresh keys.
 *
 * Two things are deliberately not scanned, recorded here so the next reader
 * does not add a click that can only hang:
 *
 *   - `.btn:disabled`. Nothing in `wire()` ever sets `disabled` on a button;
 *     `go()` clamps the step index instead, so Step at the end and Back at the
 *     start are no-ops on an enabled control. The rule is dead CSS.
 *   - the auto-play *running* state. `#autoBtn` toggles `state.autoPlay` and
 *     starts a 1500ms interval that calls `render()`, which replaces the whole
 *     document body under `#app`. Scanning that means handing axe a tree that
 *     is detached and rebuilt mid-analysis. The toggle is still driven and
 *     asserted in both directions; its only visual delta is the button's own
 *     label on a `.btn` surface every other scan already measures.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt(`step 1 of ${STEP_COUNT}, first paint`);

  // The skip link parks off-screen until focused, so the focused rendering is
  // the only one that paints.
  await page.locator('a.cl-skip-link').focus();
  await scanAt('skip link focused');

  // ── Every message in the handshake ────────────────────────────────────────
  for (let step = 2; step <= STEP_COUNT; step++) {
    await page.locator('#nextBtn').click();
    await expect(page.locator('.progress')).toHaveText(`Step ${step} / ${STEP_COUNT}`);
    await expect(page.locator('.msg.current')).toHaveCount(1);
    await expect(page.locator('.detail h3')).not.toBeEmpty();
    // Steps 2 and 3 are the first message in each direction, so between them
    // they flash both lane heads — the CLIENT head and the SERVER head are
    // different inks and have to be measured separately.
    if (step <= 3) await expectFlashLegible(page, `${theme} / arrival flash at step ${step}`);
    // Then let it expire, so what `scan` measures is the same frame every run.
    await expect(page.locator('.lane-heads .flash')).toHaveCount(0);
    await scanAt(`step ${step} of ${STEP_COUNT}`);
  }
  // Every key the schedule derives has now been printed at least once.
  await expect(page.locator('.detail .keyrow').first()).toBeVisible();

  // Back, then a direct jump from the ladder — two different routes to a step,
  // and the one that leaves rows after the current one un-reached again.
  await page.locator('#prevBtn').click();
  await expect(page.locator('.progress')).toHaveText(`Step ${STEP_COUNT - 1} / ${STEP_COUNT}`);
  await page.locator('.msg[data-step="2"]').click();
  await expect(page.locator('.progress')).toHaveText(`Step 3 / ${STEP_COUNT}`);
  await expect(page.locator('.msg.seen')).toHaveCount(2);
  await expect(page.locator('.lane-heads .flash')).toHaveCount(0);
  await expectNotClipped(page, '.detail .tx-chip', `${theme} / ladder jump to step 3`);
  await scanAt('jumped back to step 3 from the ladder');

  // Auto-play, on and off. The running state is not scanned — see the note
  // above — but the toggle itself is driven so a broken one fails here.
  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#autoBtn').click();
  await expect(page.locator('#autoBtn')).toHaveAttribute('aria-pressed', 'false');

  // ── The HKDF derivation, behind a closed <details> ────────────────────────
  await page.locator('.deriv > summary').click();
  await expect(page.locator('.deriv')).toHaveAttribute('open', '');
  await expect(page.locator('.deriv-out')).toBeVisible();
  await expect(page.locator('.deriv-arg')).toHaveCount(4);
  await expectNotClipped(page, '.deriv-out', `${theme} / HKDF derivation open`);
  await scanAt('HKDF derivation disclosure open');

  // ── Break this handshake ──────────────────────────────────────────────────
  // The honest panel is all-passing; each fault re-runs the real handshake and
  // reports the verifier's own booleans, so the pill mixtures are results, not
  // decoration.
  await expect(page.locator('.fault-panel .pill.good')).toHaveCount(4);
  await scanAt('fault panel, honest session');

  // ECDHE fault: authentication still holds while both Finished MACs fail —
  // the only state with passing and failing pills together on the dashed
  // faulted surface.
  await page.locator('.fault-buttons [data-fault="ecdhe"]').click();
  await expect(page.locator('.fault-panel.faulted')).toBeVisible();
  await expect(page.locator('.fault-panel .pill.good')).toHaveCount(1);
  await expect(page.locator('.fault-panel .pill.bad')).toHaveCount(3);
  await expect(page.locator('.fault-detail')).toBeVisible();
  await scanAt('fault: ECDHE agreement broken');

  // Transcript fault: CertificateVerify fails too, so the mixture differs.
  await page.locator('.fault-buttons [data-fault="transcript"]').click();
  await expect(page.locator('.fault-panel.faulted')).toBeVisible();
  await expect(page.locator('.fault-panel .pill.bad')).toHaveCount(3);
  await expect(page.locator('.fault-panel .pill.good')).toHaveCount(1);
  await scanAt('fault: a byte flipped in flight');

  await page.locator('.fault-buttons [data-fault="none"]').click();
  await expect(page.locator('.fault-panel.faulted')).toHaveCount(0);

  // ── The attacker's three moves ────────────────────────────────────────────
  // Driven after the faults, because choosing a fault clears `state.mitm`.
  for (const attack of ['reuse-cert', 'own-key', 'relay'] as const) {
    await page.locator(`.mitm-buttons [data-attack="${attack}"]`).click();
    await expect(page.locator('.mitm-box')).toBeVisible();
    await expect(page.locator('.mitm-checks li')).toHaveCount(5);
    await expect(page.locator(`.mitm-buttons [data-attack="${attack}"]`)).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    await expectNotClipped(page, '.mitm-box', `${theme} / MITM: ${attack}`);
    await scanAt(`MITM move: ${attack}`);
  }
  // All three are blocked, and that is the lab's whole point rather than a gap
  // in the drive. `attackBlocked` is `!clientAccepts || !attackerHoldsSessionSecret`:
  // `reuse-cert` and `own-key` are rejected outright (a chain the anchor does
  // not cover, or a signature the presented leaf key cannot make), and `relay`
  // is accepted but leaves the attacker holding nothing, because it never
  // injected a key share. So `mc-bad` — which needs `clientAccepts &&
  // attackerHoldsSessionSecret` — and the `⚠ ATTACK SUCCEEDED` banner are
  // unreachable from the UI. That is a fact about `runMitmAttempt`, recorded
  // here so the next reader does not go looking for a click that reaches them.
  await expect(page.locator('.mitm-box.blocked')).toHaveCount(1);
  await expect(page.locator('.mitm-checks .mc-bad')).toHaveCount(0);

  // ── A new session ─────────────────────────────────────────────────────────
  await page.locator('#resetBtn').click();
  await expect(page.locator('.progress')).toHaveText(`Step 1 / ${STEP_COUNT}`);
  await expect(page.locator('.mitm-box')).toHaveCount(0);
  await scanAt('new session, back to step 1');
}
