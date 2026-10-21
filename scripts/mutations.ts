/** Replay source mutations against committed protocol behaviour, before deployment. */
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

const mutations = JSON.parse(readFileSync('scripts/mutation-ledger.json', 'utf8')) as Mutation[];
const childEnv = { ...process.env, CI: '1', NO_COLOR: '1' };
delete childEnv.FORCE_COLOR;

function run(command: string, args: string[], expectSuccess = true) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(), env: childEnv, encoding: 'utf8',
    timeout: 180_000, maxBuffer: 16 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.error || result.signal || result.status === null) {
    throw new Error(`${command} did not complete normally: ${result.error?.message ?? result.signal}`);
  }
  if (expectSuccess && result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed (${result.status})\n${output}`);
  }
  return { status: result.status, stdout: result.stdout, output };
}

function bundleHash(): string {
  const assets = join(process.cwd(), 'dist', 'assets');
  const files = readdirSync(assets).filter((name) => name.endsWith('.js')).sort();
  if (files.length === 0) throw new Error('build emitted no JavaScript bundle');
  const hash = createHash('sha256');
  for (const file of files) hash.update(file).update(readFileSync(join(assets, file)));
  return hash.digest('hex');
}

function owningTest(marker: string, expectedStatus: 'passed' | 'failed'): void {
  const result = run('npx', [
    '--no-install', 'playwright', 'test', 'e2e/claims.spec.ts', 'e2e/resumption-protocol.spec.ts',
    '--grep', `\\[verdict:${marker}\\]`, '--retries=0', '--workers=1', '--reporter=json',
  ], expectedStatus === 'passed');
  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new Error(`${marker}: no valid Playwright JSON report\n${result.output}`);
  }
  if (report.errors?.length) throw new Error(`${marker}: infrastructure failure: ${JSON.stringify(report.errors)}`);
  const specs: any[] = [];
  function visit(suite: any): void {
    specs.push(...(suite.specs ?? []));
    for (const child of suite.suites ?? []) visit(child);
  }
  for (const suite of report.suites ?? []) visit(suite);
  if (specs.length !== 1 || !specs[0].title.includes(`[verdict:${marker}]`)) {
    throw new Error(`${marker}: expected exactly one owning test, got ${specs.map((spec) => spec.title).join(', ')}`);
  }
  const tests = specs[0].tests ?? [];
  if (tests.length !== 1 || tests[0].expectedStatus !== 'passed' || tests[0].results?.length !== 1) {
    throw new Error(`${marker}: missing, skipped, expected-failure or retried tests cannot prove a kill`);
  }
  const observed = tests[0].results[0];
  if (observed.status !== expectedStatus || (expectedStatus === 'failed' && result.status === 0)) {
    throw new Error(`${marker}: expected ${expectedStatus}, got ${observed.status}; timeouts are not kills`);
  }
  if (expectedStatus === 'failed' && observed.errors?.some((error: any) =>
    /at boot\b|browserType\.launch|page\.goto|Test timeout|webServer/i.test(`${error.message ?? ''}\n${error.stack ?? ''}`))) {
    throw new Error(`${marker}: startup, navigation or infrastructure failure cannot prove a kill`);
  }
  if (expectedStatus === 'failed' && !observed.errors?.some((error: any) =>
    /\bexpect\(|AssertionError/.test((error.message ?? '').replace(/\u001b\[[0-9;]*m/g, '')))) {
    throw new Error(`${marker}: failure was not a named assertion: ${JSON.stringify(observed.errors)}`);
  }
}

const dirty = run('git', ['status', '--porcelain']).output.trim();
if (dirty) throw new Error(`mutation gate requires a clean committed tree:\n${dirty}`);
run('npm', ['run', 'build']);
const baselineHash = bundleHash();

for (const mutation of mutations) {
  const original = readFileSync(mutation.file, 'utf8');
  if (original.split(mutation.anchor).length !== 2) {
    throw new Error(`${mutation.marker}: source anchor must occur exactly once`);
  }
  owningTest(mutation.marker, 'passed');
  console.log(`[${mutation.marker}] baseline green`);
  try {
    writeFileSync(mutation.file, original.replace(mutation.anchor, mutation.replacement));
    if (!run('git', ['diff', '--', mutation.file]).output.trim()) throw new Error('source diff is empty');
    run('npm', ['run', 'build']); // Compile/build failure never counts as a kill.
    const mutantHash = bundleHash();
    if (mutantHash === baselineHash) throw new Error(`${mutation.marker}: production bundle hash did not move`);
    owningTest(mutation.marker, 'failed');
    console.log(`[${mutation.marker}] source diff non-empty; bundle ${baselineHash.slice(0, 12)} -> ${mutantHash.slice(0, 12)}; named assertion red`);
  } finally {
    writeFileSync(mutation.file, original);
    run('npm', ['run', 'build']);
    if (bundleHash() !== baselineHash) throw new Error(`${mutation.marker}: restored bundle differs`);
    owningTest(mutation.marker, 'passed');
    if (run('git', ['diff', 'HEAD', '--', mutation.file]).output.trim()) throw new Error('source did not restore cleanly');
    console.log(`[${mutation.marker}] source restored; original bundle hash; named test green`);
  }
}
console.log(`MUTATIONS PASS: ${mutations.length} of ${mutations.length} behavioural source mutations killed`);
