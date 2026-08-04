import { expect, test as base, type Locator, type Page } from '@playwright/test';

/**
 * Functional claim gate for the TLS 1.3 Handshake lab.
 *
 * The a11y suite proves the page is reachable and readable. Nothing proved that
 * the things it *says* are true: that the honest run really reports four passing
 * verdicts, that each injectable fault really reaches a failing state and names
 * which check caught it, that the MITM verdict follows from the checks printed
 * directly above it, and that the numbers on screen add up.
 *
 * Every assertion below is anchored to a value the page computed for THIS
 * session wherever one exists — the transcript hash the MITM panel calls "the
 * genuine session" is compared against the hash the Certificate step actually
 * rendered, not against a hardcoded digest. Hardcoded strings appear only for
 * labels the page owns as prose.
 */

/** Fail any test in which the page threw an uncaught exception. */
const test = base.extend<{ pageErrors: void }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (e) => errors.push(`${e.name}: ${e.message}`));
      await use();
      expect(errors, 'uncaught page exceptions').toEqual([]);
    },
    { auto: true },
  ],
});

const STEP_TITLES = [
  'ClientHello',
  'ServerHello',
  'EncryptedExtensions',
  'Certificate',
  'CertificateVerify',
  'Finished (server)',
  'Finished (client)',
  'Application Data',
];

/** The four verdict pills in "Break this handshake", in render order. */
const FAULT_VERDICTS = [
  'ECDHE outputs agree',
  'CertificateVerify verifies over the transcript the client hashed',
  'client accepts the server Finished MAC',
  'server accepts the client Finished MAC',
];

async function openApp(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('.shell')).toBeVisible();
  await expect(page.locator('#nextBtn')).toBeVisible();
}

/** ✓/✗ state of every pill inside a container, keyed by its label text. */
async function pills(scope: Locator): Promise<Record<string, boolean>> {
  return scope.evaluate((el) => {
    const out: Record<string, boolean> = {};
    for (const p of el.querySelectorAll('.pill')) {
      const label = (p.textContent ?? '').replace(/^[✓✗]\s*/, '').trim();
      // The tick and the CSS class are rendered from the same boolean; if they
      // ever disagree the page is lying in one of the two, so require both.
      const tick = (p.textContent ?? '').trim().startsWith('✓');
      const good = p.classList.contains('good');
      if (tick !== good) throw new Error(`pill icon/class disagree: ${p.outerHTML}`);
      out[label] = good;
    }
    return out;
  });
}

/** The concatenated hex of a .secret-bytes row, plus which byte cells differ. */
async function secretRow(page: Page, index: number): Promise<{ hex: string; diffs: number[] }> {
  return page.evaluate((i) => {
    const row = document.querySelectorAll('.secret-bytes')[i];
    if (!row) throw new Error(`no .secret-bytes[${i}]`);
    const cells = [...row.querySelectorAll('.byte')];
    return {
      hex: cells.map((c) => c.textContent ?? '').join(''),
      diffs: cells.flatMap((c, n) => (c.classList.contains('diff') ? [n] : [])),
    };
  }, index);
}

/** Label + value of the transcript chip on the step currently shown. */
async function transcriptChip(page: Page): Promise<{ label: string; value: string; binding: boolean }> {
  return page.evaluate(() => {
    const chip = document.querySelector('.tx-chip');
    if (!chip) throw new Error('no transcript chip');
    return {
      label: chip.querySelector('.tx-label')?.textContent?.trim() ?? '',
      value: chip.querySelector('.tx-val')?.textContent?.trim() ?? '',
      binding: chip.classList.contains('binding'),
    };
  });
}

/** The MITM result box, read back as the booleans it is displaying. */
async function mitmResult(page: Page) {
  return page.evaluate(() => {
    const box = document.querySelector('.mitm-box');
    if (!box) throw new Error('no MITM result box');
    const checks: Record<string, boolean> = {};
    for (const li of box.querySelectorAll('.mitm-checks li')) {
      const label = li.querySelector('.mc-label')?.textContent?.trim() ?? '';
      const raw = li.querySelector('.mc-val')?.textContent?.trim() ?? '';
      if (raw !== 'YES' && raw !== 'NO') throw new Error(`unreadable check value ${raw}`);
      checks[label] = raw === 'YES';
    }
    const rows = [...box.querySelectorAll('.tx-cmp-row')].map((r) => ({
      tag: r.querySelector('.tx-cmp-tag')?.textContent?.trim() ?? '',
      hash: r.querySelector('.tx-cmp-hash')?.textContent?.trim() ?? '',
    }));
    return {
      blockedClass: box.classList.contains('blocked'),
      headline: box.querySelector('strong')?.textContent?.trim() ?? '',
      presented: (box.querySelector('.mono')?.textContent ?? '').replace(/\s+/g, ' ').trim(),
      checks,
      genuineHash: rows[0]?.hash ?? '',
      clientHash: rows[1]?.hash ?? '',
      notes: [...box.querySelectorAll('.tx-cmp-note')].map((n) => (n.textContent ?? '').replace(/\s+/g, ' ').trim()),
      explanation: [...box.querySelectorAll('ol li')].map((e) => (e.textContent ?? '').replace(/\s+/g, ' ').trim()),
    };
  });
}

const CHECK_ECDHE = 'client completed ECDHE with the peer it saw';
const CHECK_CHAIN = "presented chain validates under the client's trust anchor";
const CHECK_CV = 'CertificateVerify verifies under the presented leaf key';
const CHECK_ACCEPT = 'client accepts the handshake';
const CHECK_HOLDS = 'attacker ends up holding the session secret';

test.beforeEach(async ({ page }) => {
  await openApp(page);
});

// ---------------------------------------------------------------------------
// The headline verdict
// ---------------------------------------------------------------------------

test('honest session: every verdict the page prints is a pass, and it says so', async ({ page }) => {
  const panel = page.locator('.fault-panel');
  await expect(panel).not.toHaveClass(/faulted/);
  await expect(page.locator('.fault-detail')).toHaveCount(0);

  const verdicts = await pills(panel);
  expect(Object.keys(verdicts).sort()).toEqual([...FAULT_VERDICTS].sort());
  expect(verdicts).toEqual(Object.fromEntries(FAULT_VERDICTS.map((v) => [v, true])));

  // The summary sentence is a function of those four booleans, so it has to
  // agree with them rather than being a fixed caption.
  await expect(page.locator('.fault-note')).toContainText('All four hold, so this session completes');

  // Section 4 (chain + CertificateVerify) and section 6 (AEAD) likewise.
  const auth = await pills(page.locator('.panel', { has: page.locator('.chain') }).locator('.verdicts').first());
  expect(auth).toEqual({
    'root matches trust anchor': true,
    'root self-signature valid': true,
    'leaf signed by root': true,
    'CertificateVerify signature valid': true,
  });
  const record = await pills(page.locator('.record-grid').locator('xpath=..').locator('.verdicts'));
  expect(record).toEqual({
    'decrypts back to the exact plaintext': true,
    'one flipped byte → GCM rejects it': true,
  });
});

test('key exchange: the agreement pill agrees with the bytes rendered under it', async ({ page }) => {
  const clientRow = await secretRow(page, 0);
  const serverRow = await secretRow(page, 1);

  expect(clientRow.hex).toHaveLength(64); // 32 bytes
  expect(serverRow.hex).toHaveLength(64);
  // Both cards render the same comparison from opposite sides; if the highlight
  // is computed at all, the two must mark the same positions.
  expect(clientRow.diffs).toEqual(serverRow.diffs);

  const kx = await pills(page.locator('.kx-note + .lead'));
  const claimed = kx['both sides independently computed the same 32-byte ECDHE secret'];
  // The claim is only true if the two independently rendered secrets really are
  // byte-identical — that equality, not the pill, is the ground truth here.
  expect(claimed).toBe(clientRow.hex === serverRow.hex);
  expect(claimed).toBe(clientRow.diffs.length === 0);
  expect(claimed).toBe(true);
});

// ---------------------------------------------------------------------------
// Failure paths — reached, and attributed
// ---------------------------------------------------------------------------

test('ECDHE fault: Finished fails on both sides, authentication does not, and the page names the mismatch', async ({
  page,
}) => {
  await page.locator('.fault-buttons [data-fault="ecdhe"]').click();
  await expect(page.locator('.fault-panel.faulted')).toBeVisible();
  await expect(page.locator('.fault-buttons [data-fault="ecdhe"]')).toHaveAttribute('aria-pressed', 'true');

  expect(await pills(page.locator('.fault-panel'))).toEqual({
    'ECDHE outputs agree': false,
    'CertificateVerify verifies over the transcript the client hashed': true,
    'client accepts the server Finished MAC': false,
    'server accepts the client Finished MAC': false,
  });

  // Not merely "something failed": the detail line has to identify the cause in
  // this run's own numbers, and those numbers must match the secrets on screen.
  const detail = (await page.locator('.fault-detail').textContent()) ?? '';
  const m = detail.match(/client ECDHE output ([0-9a-f]{8})… vs server ([0-9a-f]{8})…/);
  expect(m, `fault detail did not name the two ECDHE outputs: ${detail}`).not.toBeNull();
  const clientRow = await secretRow(page, 0);
  const serverRow = await secretRow(page, 1);
  expect(m![1]).toBe(clientRow.hex.slice(0, 8));
  expect(m![2]).toBe(serverRow.hex.slice(0, 8));
  expect(clientRow.hex).not.toBe(serverRow.hex);
  expect(clientRow.diffs.length).toBeGreaterThan(0);

  await expect(page.locator('.fault-note')).toContainText('Finished is the check that catches this');

  // The lesson only lands if the checks it must NOT disturb stay green.
  const auth = await pills(page.locator('.panel', { has: page.locator('.chain') }).locator('.verdicts').first());
  expect(auth['CertificateVerify signature valid']).toBe(true);
  expect(auth['leaf signed by root']).toBe(true);
  expect(auth['root matches trust anchor']).toBe(true);
});

test('in-flight byte flip: every transcript-bound check fails at once, ECDHE still agrees', async ({ page }) => {
  await page.locator('.fault-buttons [data-fault="transcript"]').click();
  await expect(page.locator('.fault-panel.faulted')).toBeVisible();

  expect(await pills(page.locator('.fault-panel'))).toEqual({
    'ECDHE outputs agree': true,
    'CertificateVerify verifies over the transcript the client hashed': false,
    'client accepts the server Finished MAC': false,
    'server accepts the client Finished MAC': false,
  });

  const detail = (await page.locator('.fault-detail').textContent()) ?? '';
  const m = detail.match(
    /byte 3 of EncryptedExtensions flipped in flight \((\d+) → (\d+)\); client transcript ([0-9a-f]{8})… vs server ([0-9a-f]{8})…/,
  );
  expect(m, `fault detail did not name the flipped byte and both transcripts: ${detail}`).not.toBeNull();
  // A one-bit flip: the before/after byte values must differ in exactly the low bit.
  expect(Number(m![1]) ^ Number(m![2])).toBe(1);
  // And the two transcripts it blames must actually be different values.
  expect(m![3]).not.toBe(m![4]);

  await expect(page.locator('.fault-note')).toContainText('transcript binding doing its job');

  // Chain validation is untouched by a transcript flip; the signature check is not.
  const auth = await pills(page.locator('.panel', { has: page.locator('.chain') }).locator('.verdicts').first());
  expect(auth).toEqual({
    'root matches trust anchor': true,
    'root self-signature valid': true,
    'leaf signed by root': true,
    'CertificateVerify signature valid': false,
  });

  // The key exchange panel must not inherit the alarm — its own pill is still a pass.
  const clientRow = await secretRow(page, 0);
  const serverRow = await secretRow(page, 1);
  expect(clientRow.hex).toBe(serverRow.hex);
});

test('every fault choice is reachable and returns to a clean state', async ({ page }) => {
  // "Every" has to mean every one the page offers, not every one this file
  // happens to list. Pin the offered set so a newly added fault fails here
  // until it has expectations of its own, rather than passing unexercised.
  const offered = await page.locator('.fault-buttons [data-fault]').evaluateAll((els) =>
    els.map((e) => e.getAttribute('data-fault')),
  );
  expect(offered.slice().sort()).toEqual(['ecdhe', 'none', 'transcript']);

  for (const fault of ['ecdhe', 'transcript']) {
    await page.locator(`.fault-buttons [data-fault="${fault}"]`).click();
    await expect(page.locator('.fault-panel.faulted')).toBeVisible();
    await expect(page.locator('.fault-panel .pill.bad')).not.toHaveCount(0);
    await expect(page.locator('.fault-detail')).not.toBeEmpty();
  }
  await page.locator('.fault-buttons [data-fault="none"]').click();
  await expect(page.locator('.fault-panel')).not.toHaveClass(/faulted/);
  await expect(page.locator('.fault-panel .pill.bad')).toHaveCount(0);
  await expect(page.locator('.fault-detail')).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// The walkthrough: counters, and the transcript values it exists to show
// ---------------------------------------------------------------------------

test('ladder: the progress counter, the rendered rows and the detail card stay in step', async ({ page }) => {
  const rows = page.locator('.msg[data-step]');
  await expect(rows).toHaveCount(STEP_TITLES.length);

  const progress = page.locator('.progress');
  const total = Number(((await progress.textContent()) ?? '').match(/\/\s*(\d+)/)?.[1]);
  // The "/ N" is rendered from steps.length; the rows are rendered from the same
  // array. A mismatch means the counter is describing a different walkthrough.
  expect(total).toBe(await rows.count());

  for (let i = 0; i < STEP_TITLES.length; i++) {
    if (i > 0) await page.locator('#nextBtn').click();
    await expect(progress).toHaveText(`Step ${i + 1} / ${total}`);
    await expect(rows.nth(i)).toHaveAttribute('aria-current', 'step');
    await expect(page.locator('.msg[aria-current="step"]')).toHaveCount(1);
    await expect(page.locator('.detail h3')).toContainText(STEP_TITLES[i]!);

    // The byte count is printed twice, from one value. They must agree.
    const rowBytes = ((await rows.nth(i).locator('.bytes').textContent()) ?? '').match(/^(\d+) B/)?.[1];
    const detailBytes = ((await page.locator('.detail .dir').textContent()) ?? '').match(/(\d+) bytes on the wire/)?.[1];
    expect(detailBytes, `step ${i + 1} byte count`).toBe(rowBytes);
  }

  // Clamped at the end, and Back walks it down again.
  await page.locator('#nextBtn').click();
  await expect(progress).toHaveText(`Step ${total} / ${total}`);
  await page.locator('#prevBtn').click();
  await expect(progress).toHaveText(`Step ${total - 1} / ${total}`);

  // Arrow keys are the documented alternative control.
  await page.locator('body').press('ArrowLeft');
  await expect(progress).toHaveText(`Step ${total - 2} / ${total}`);
  await page.locator('body').press('ArrowRight');
  await expect(progress).toHaveText(`Step ${total - 1} / ${total}`);
});

test('transcript chips name the run they cover, and a signature covers the message before it', async ({ page }) => {
  const chipFor = async (step: number) => {
    await page.locator(`.msg[data-step="${step}"]`).click();
    return transcriptChip(page);
  };

  const clientHello = await chipFor(0);
  expect(clientHello.label).toBe('SHA-256(ClientHello)');
  expect(clientHello.binding).toBe(false);

  const certificate = await chipFor(3);
  expect(certificate.label).toBe('SHA-256(ClientHello..Certificate)');

  const certVerify = await chipFor(4);
  // The claim the README makes: CertificateVerify signs the transcript ending
  // just BEFORE it, so its chip must be the Certificate step's value, not a
  // hash that includes CertificateVerify itself.
  expect(certVerify.label).toBe('SHA-256(ClientHello..Certificate)');
  expect(certVerify.value).toBe(certificate.value);
  expect(certVerify.binding).toBe(true);
  await expect(page.locator('.tx-bind')).toContainText('is what gets SIGNED here');

  const serverFinished = await chipFor(5);
  expect(serverFinished.label).toBe('SHA-256(ClientHello..CertificateVerify)');
  expect(serverFinished.value).not.toBe(certVerify.value);
  expect(serverFinished.binding).toBe(true);
  await expect(page.locator('.tx-bind')).toContainText("is what gets MAC'd here");

  // Every step must carry a chip, and consecutive runs must actually differ
  // where the covered run differs — a frozen chip would make the exhibit a prop.
  const seen = new Map<string, string>();
  for (let i = 0; i < STEP_TITLES.length; i++) {
    const chip = await chipFor(i);
    expect(chip.value, `step ${i + 1} chip`).toMatch(/^[0-9a-f]{12}…[0-9a-f]{12}$/);
    const prior = seen.get(chip.label);
    if (prior !== undefined) expect(chip.value).toBe(prior); // same run ⇒ same hash
    seen.set(chip.label, chip.value);
  }
  // Six distinct runs of messages are covered across the eight steps: two pairs
  // of steps share a label (CertificateVerify reuses the Certificate transcript,
  // Application Data reuses the client Finished one) because in TLS 1.3 they
  // genuinely cover the same messages. Pin the count, or a bug that collapsed
  // every chip onto one label would still satisfy the distinctness check below.
  expect(seen.size).toBe(6);
  expect(new Set(seen.values()).size).toBe(seen.size);
});

// ---------------------------------------------------------------------------
// The MITM exhibit
// ---------------------------------------------------------------------------

test('MITM: every strategy reaches a verdict that follows from the checks printed above it', async ({ page }) => {
  // The value section 2 shows after Certificate — what the panel below calls
  // "the genuine session" transcript. Read it from the page, not from a fixture.
  await page.locator('.msg[data-step="3"]').click();
  const genuineTranscript = (await transcriptChip(page)).value;
  const genuineLeaf = ((await page.locator('.chain .cert').nth(1).locator('.mono').textContent()) ?? '').match(
    /Ed25519 pub: (\S+)/,
  )?.[1];
  expect(genuineLeaf).toBeTruthy();

  // Same reason as the fault test: the branch below asserts a distinct outcome
  // per strategy, so an unlisted strategy would otherwise be silently skipped
  // while this test still called itself exhaustive.
  const offered = await page.locator('.mitm-buttons [data-attack]').evaluateAll((els) =>
    els.map((e) => e.getAttribute('data-attack')),
  );
  expect(offered.slice().sort()).toEqual(['own-key', 'relay', 'reuse-cert']);

  for (const attack of ['reuse-cert', 'own-key', 'relay'] as const) {
    await page.locator(`.mitm-buttons [data-attack="${attack}"]`).click();
    await expect(page.locator('.mitm-box')).toBeVisible();
    const r = await mitmResult(page);

    expect(Object.keys(r.checks).sort()).toEqual(
      [CHECK_ECDHE, CHECK_CHAIN, CHECK_CV, CHECK_ACCEPT, CHECK_HOLDS].sort(),
    );

    // Internal consistency: the two derived rows must equal the AND / the safety
    // condition of the rows above them, in the panel's own displayed values.
    expect(r.checks[CHECK_ACCEPT], `${attack}: accept = chain AND certVerify`).toBe(
      r.checks[CHECK_CHAIN]! && r.checks[CHECK_CV]!,
    );
    const blocked = !(r.checks[CHECK_ACCEPT]! && r.checks[CHECK_HOLDS]!);
    expect(r.blockedClass, `${attack}: blocked styling`).toBe(blocked);
    expect(r.headline).toContain(blocked ? '🛡 attack blocked' : '⚠ ATTACK SUCCEEDED');

    // The panel is attacking THIS session, so the transcript it labels genuine
    // must be the one section 2 rendered.
    expect(r.genuineHash, `${attack}: genuine transcript`).toBe(genuineTranscript);
    const differ = r.clientHash !== r.genuineHash;
    expect(r.notes[0]).toContain(differ ? 'Different —' : 'Identical —');

    // Key exchange always completes; that is the whole point of the exhibit.
    expect(r.checks[CHECK_ECDHE]).toBe(true);

    if (attack === 'reuse-cert') {
      // Holds a copied certificate but not its private key: the chain passes,
      // the signature does not, and the panel must say which one broke.
      expect(r.checks[CHECK_CHAIN]).toBe(true);
      expect(r.checks[CHECK_CV]).toBe(false);
      expect(r.checks[CHECK_HOLDS]).toBe(true);
      expect(r.presented).toContain('(the genuine server leaf)');
      expect(r.presented).toContain(genuineLeaf!);
      expect(r.explanation.join(' ')).toContain('CertificateVerify check against the presented leaf key: FAILS');
    } else if (attack === 'own-key') {
      // Signs correctly, with a key nobody trusts: the trust anchor is the check
      // that trips, and the leaf on screen must not be the genuine one.
      expect(r.checks[CHECK_CHAIN]).toBe(false);
      expect(r.checks[CHECK_CV]).toBe(true);
      expect(r.checks[CHECK_HOLDS]).toBe(true);
      expect(r.presented).toContain('NOT the genuine leaf');
      expect(r.presented).toContain(genuineLeaf!);
      expect(r.explanation.join(' ')).toContain('anchor matches: false');
    } else {
      // Relaying passes every check and gains the attacker nothing.
      expect(r.checks[CHECK_CHAIN]).toBe(true);
      expect(r.checks[CHECK_CV]).toBe(true);
      expect(r.checks[CHECK_ACCEPT]).toBe(true);
      expect(r.checks[CHECK_HOLDS]).toBe(false);
      expect(r.clientHash).toBe(genuineTranscript);
      expect(r.notes[1]).toContain('would be accepted');
      expect(r.explanation.join(' ')).toContain('a wire, not a listener');
    }
  }
});

test('MITM verdicts never go stale: re-running the handshake clears the previous result', async ({ page }) => {
  await page.locator('.mitm-buttons [data-attack="own-key"]').click();
  await expect(page.locator('.mitm-box')).toBeVisible();

  // A fault re-runs the whole handshake, so last run's verdict must not survive.
  await page.locator('.fault-buttons [data-fault="ecdhe"]').click();
  await expect(page.locator('.mitm-box')).toHaveCount(0);

  // New session likewise.
  await page.locator('.mitm-buttons [data-attack="relay"]').click();
  await expect(page.locator('.mitm-box')).toBeVisible();
  await page.locator('#resetBtn').click();
  await expect(page.locator('.mitm-box')).toHaveCount(0);

  // And a fresh result must describe the NEW session, not the old one.
  await page.locator('.msg[data-step="3"]').click();
  const genuine = (await transcriptChip(page)).value;
  await page.locator('.mitm-buttons [data-attack="relay"]').click();
  expect((await mitmResult(page)).genuineHash).toBe(genuine);
});

// ---------------------------------------------------------------------------
// Forward secrecy, as the README says a user can confirm it
// ---------------------------------------------------------------------------

test('New session rotates the ephemeral material and keeps the long-term identity', async ({ page }) => {
  const snapshot = () =>
    page.evaluate(() => ({
      leaf: [...document.querySelectorAll('.chain .cert .mono')].map((e) => e.textContent?.trim() ?? ''),
      schedule: [...document.querySelectorAll('.kstage .val')].map((e) => e.textContent ?? ''),
      secret: document.querySelector('.secret-bytes')?.textContent ?? '',
      record: document.querySelector('.record-grid .codebox.ct')?.textContent ?? '',
    }));

  await page.locator('#nextBtn').click();
  const before = await snapshot();
  await page.locator('#resetBtn').click();
  await expect(page.locator('.progress')).toHaveText(/Step 1 \//); // reset returns to the start
  const after = await snapshot();

  // Long-term identity survives — that is the contrast the page is drawing.
  expect(after.leaf).toEqual(before.leaf);

  // Everything ephemeral changes.
  expect(after.secret).not.toBe(before.secret);
  expect(after.record).not.toBe(before.record);

  // The Early Secret is HKDF-Extract over all-zeros when there is no PSK, so it
  // is a protocol constant and cannot rotate; every secret that descends from
  // the ECDHE output must. The page used to promise "every secret above
  // changes", which its own first row contradicted on every reset — this pins
  // the corrected claim to the observed behaviour.
  expect(after.schedule).toHaveLength(8);
  expect(after.schedule[0]).toBe(before.schedule[0]);
  await expect(page.locator('.kstage .name').first()).toHaveText(/Early Secret\s+\(constant — no PSK\)/);
  await expect(page.locator('.panel', { has: page.locator('.schedule') })).toContainText(
    'every secret below the Early Secret changes',
  );
  for (let i = 1; i < after.schedule.length; i++) {
    expect(after.schedule[i], `schedule row ${i} did not rotate`).not.toBe(before.schedule[i]);
  }
  // And they are eight distinct branches, not one value repeated.
  expect(new Set(after.schedule).size).toBe(8);
});

// ---------------------------------------------------------------------------
// The numbers add up
// ---------------------------------------------------------------------------

test('record layer: the header, the ciphertext and the plaintext lengths agree', async ({ page }) => {
  const r = await page.evaluate(() => {
    const fields = [...document.querySelectorAll('.record-grid .field')].map((f) => ({
      label: f.querySelector('label')?.textContent?.trim() ?? '',
      value: f.querySelector('.codebox')?.textContent ?? '',
    }));
    return {
      plaintext: fields[0]!.value,
      nonce: fields[1]!.value,
      aad: fields[2]!.value,
      ctLabel: fields[3]!.label,
      ct: fields[3]!.value,
    };
  });

  expect(r.nonce).toMatch(/^[0-9a-f]{24}$/); // 12-byte AEAD nonce
  expect(r.ct).toMatch(/^[0-9a-f]+$/);

  // The label's byte count must match the hex actually printed beside it.
  const labelled = Number(r.ctLabel.match(/\((\d+) B\)/)?.[1]);
  expect(labelled).toBe(r.ct.length / 2);

  // AAD is type ‖ legacy_version ‖ length. The declared length is the record
  // header's promise about the ciphertext; it must be the ciphertext's real size.
  expect(r.aad).toMatch(/^170303[0-9a-f]{4}$/);
  expect(parseInt(r.aad.slice(6), 16)).toBe(labelled);

  // And the whole is its parts: plaintext ‖ content-type(1) ‖ GCM tag(16).
  // The DOM normalizes the request's CRLFs to LF, so re-expand them to count bytes.
  const plaintextBytes = new TextEncoder().encode(r.plaintext.replace(/\n/g, '\r\n')).length;
  expect(plaintextBytes + 1 + 16).toBe(labelled);

  const pillStates = await pills(page.locator('.record-grid').locator('xpath=..').locator('.verdicts'));
  expect(Object.values(pillStates).every(Boolean)).toBe(true);
});

test('key schedule: the worked derivation states the same length its own bars measure', async ({ page }) => {
  await expect(page.locator('.kstage')).toHaveCount(8);
  await page.locator('.deriv summary').click();

  const d = await page.evaluate(() => {
    const args = [...document.querySelectorAll('.deriv-arg')].map((a) => ({
      key: a.querySelector('.deriv-k')?.textContent?.trim() ?? '',
      value: (a.querySelector('.deriv-v')?.textContent ?? '').replace(/\s+/g, ' ').trim(),
    }));
    return {
      args: Object.fromEntries(args.map((a) => [a.key, a.value])),
      bars: [...document.querySelectorAll('.deriv-bar-len')].map((e) => e.textContent?.trim() ?? ''),
      parent: document.querySelector('.deriv-args .hl')?.textContent?.trim() ?? '',
      scheduleHandshakeSecret:
        [...document.querySelectorAll('.kstage')]
          .find((k) => (k.querySelector('.name')?.textContent ?? '').startsWith('Handshake Secret'))
          ?.querySelector('.val')?.textContent ?? '',
      outName: document.querySelector('.deriv-out .deriv-k')?.textContent?.trim() ?? '',
    };
  });

  // The stated output length comes from the derived array; the bar's length is
  // measured off the rendered hex. Two sources, one number.
  const stated = Number(d.args['length']!.match(/^(\d+) bytes$/)?.[1]);
  expect(stated).toBe(32);
  expect(d.bars).toEqual([`${stated} B`, `${stated} B`]);

  // The "secret" argument must be the same Handshake Secret the tree above shows —
  // otherwise the worked example is a different derivation than the one it claims.
  expect(d.parent).toBe(d.scheduleHandshakeSecret);
  expect(d.args['label']).toContain('"s hs traffic"');
  expect(d.outName).toBe('server_handshake_traffic_secret');
});
