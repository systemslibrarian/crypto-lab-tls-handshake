/** Reproducible §4.1c verdict-mutation gate for the resumption extension. */
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';

interface Mutation {
  marker: string;
  file: string;
  anchor: string;
  replacement: string;
}

const mutations: Mutation[] = [
  {
    marker: 'binder-check',
    file: 'src/resumption-lab.ts',
    anchor: 'const valid = await verifyResumptionBinder(lab.issued.psk, parsed.truncated, parsed.binder);',
    replacement: 'const valid = !(await verifyResumptionBinder(lab.issued.psk, parsed.truncated, parsed.binder));',
  },
  {
    marker: 'replay-no-anti-replay',
    file: 'src/resumption-lab.ts',
    anchor: "case 'no-anti-replay':\n      verdictOk = a.executedPayments < 2;",
    replacement: "case 'no-anti-replay':\n      verdictOk = a.executedPayments <= 2;",
  },
  {
    marker: 'replay-single-use-ticket',
    file: 'src/resumption-lab.ts',
    anchor: "verdictOk = a.executedPayments === 1 && !replayA.accepted0Rtt;",
    replacement: "verdictOk = a.executedPayments === 1 && replayA.accepted0Rtt;",
  },
  {
    marker: 'replay-clienthello-recording',
    file: 'src/resumption-lab.ts',
    anchor: 'verdictOk = !replayA.accepted0Rtt && !replayB.accepted0Rtt;',
    replacement: 'verdictOk = !replayA.accepted0Rtt && replayB.accepted0Rtt;',
  },
  {
    marker: 'replay-freshness-window',
    file: 'src/resumption-lab.ts',
    anchor: "case 'freshness-window':\n      verdictOk = a.executedPayments < 2;",
    replacement: "case 'freshness-window':\n      verdictOk = a.executedPayments <= 2;",
  },
  {
    marker: 'replay-ignore-0rtt',
    file: 'src/resumption-lab.ts',
    anchor: 'verdictOk = a.executedPayments === 1 && oneRttReplayRejected;',
    replacement: 'verdictOk = a.executedPayments === 1 && !oneRttReplayRejected;',
  },
  {
    marker: 'stek-psk-ke',
    file: 'src/main.ts',
    anchor: "markedPill(!leak.pskKe.oneRttReadable, leak.pskKe.oneRttReadable ? 'ALARM — PAST SESSION READ' : 'PAST SESSION SEALED', 'stek-psk-ke', true)",
    replacement: "markedPill(leak.pskKe.oneRttReadable, leak.pskKe.oneRttReadable ? 'ALARM — PAST SESSION READ' : 'PAST SESSION SEALED', 'stek-psk-ke', true)",
  },
  {
    marker: 'stek-psk-dhe',
    file: 'src/main.ts',
    anchor: "markedPill(!(leak.pskDhe.earlyDataReadable && !leak.pskDhe.oneRttReadable), '1-RTT HOLDS — 0-RTT EXPOSED', 'stek-psk-dhe', true)",
    replacement: "markedPill(leak.pskDhe.earlyDataReadable && !leak.pskDhe.oneRttReadable, '1-RTT HOLDS — 0-RTT EXPOSED', 'stek-psk-dhe', true)",
  },
  {
    marker: 'one-rtt-fallback',
    file: 'src/main.ts',
    anchor: "markedPill(state.edgeCases.freshnessFallback.oneRttFallback, '1-RTT FALLBACK AVAILABLE', 'one-rtt-fallback', true)",
    replacement: "markedPill(!state.edgeCases.freshnessFallback.oneRttFallback, '1-RTT FALLBACK AVAILABLE', 'one-rtt-fallback', true)",
  },
];

const childEnv = { ...process.env, CI: '1', NO_COLOR: '1' };
delete childEnv.FORCE_COLOR;

function run(command: string, args: string[], expectSuccess = true): { status: number; output: string } {
  const result = spawnSync(command, args, { cwd: process.cwd(), env: childEnv, encoding: 'utf8' });
  const status = result.status ?? 1;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (expectSuccess && status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (${status})\n${output}`);
  }
  return { status, output };
}

function bundleHash(): string {
  const assets = join(process.cwd(), 'dist', 'assets');
  const files = readdirSync(assets).filter((name) => name.endsWith('.js')).sort();
  if (files.length === 0) throw new Error('build emitted no JavaScript bundle');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(join(assets, file)));
  return hash.digest('hex');
}

function replaceExactlyOnce(file: string, from: string, to: string): void {
  const source = readFileSync(file, 'utf8');
  const occurrences = source.split(from).length - 1;
  if (occurrences !== 1) throw new Error(`${file}: mutation anchor occurs ${occurrences} times (wanted 1)`);
  writeFileSync(file, source.replace(from, to));
}

function owningTest(marker: string, expectSuccess: boolean): { status: number; output: string } {
  return run(
    'npx',
    ['playwright', 'test', 'e2e/claims.spec.ts', '--grep', `\\[verdict:${marker}\\]`, '--retries=0'],
    expectSuccess,
  );
}

const dirty = run('git', ['status', '--porcelain'], true).output.trim();
if (dirty) throw new Error(`mutation gate requires a clean committed tree:\n${dirty}`);

run('npm', ['run', 'build']);
const baselineHash = bundleHash();
const killed: string[] = [];

for (const mutation of mutations) {
  owningTest(mutation.marker, true);
  replaceExactlyOnce(mutation.file, mutation.anchor, mutation.replacement);
  try {
    const diff = run('git', ['diff', '--', mutation.file]).output.trim();
    if (!diff) throw new Error(`${mutation.marker}: source diff is empty`);
    run('npm', ['run', 'build']);
    const mutatedHash = bundleHash();
    if (mutatedHash === baselineHash) throw new Error(`${mutation.marker}: bundle hash did not move`);
    const red = owningTest(mutation.marker, false);
    if (red.status === 0) throw new Error(`${mutation.marker}: owning test stayed green`);
    if (/does not build|EADDRINUSE|ERR_CONNECTION_REFUSED|webServer.*failed/i.test(red.output)) {
      throw new Error(`${mutation.marker}: red run was infrastructure/build failure\n${red.output}`);
    }
  } finally {
    replaceExactlyOnce(mutation.file, mutation.replacement, mutation.anchor);
  }

  run('npm', ['run', 'build']);
  const restoredHash = bundleHash();
  if (restoredHash !== baselineHash) throw new Error(`${mutation.marker}: restored bundle hash differs`);
  owningTest(mutation.marker, true);
  if (run('git', ['diff', '--', mutation.file]).output.trim()) {
    throw new Error(`${mutation.marker}: source did not restore cleanly`);
  }
  killed.push(mutation.marker);
  console.log(`KILLED ${mutation.marker}: baseline green; source diff non-empty; bundle hash moved; named test red; restored green`);
}

if (killed.length !== mutations.length) throw new Error(`killed ${killed.length} of ${mutations.length}`);
console.log(`MUTATIONS PASS: ${killed.length} of ${mutations.length} killed`);
