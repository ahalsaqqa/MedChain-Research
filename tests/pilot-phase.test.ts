import { jest } from '@jest/globals';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { inspect } from 'node:util';
import { formatExecError } from 'jest-message-util';
import { createPilotLog } from './helpers/pilot-log.js';
import { createPilotReporter } from './helpers/pilot-phase.js';

describe('actual pilot phase public failure boundary (no proof generation)', () => {
  const parent = resolve('work/task-6-pilot-tests');
  let directory: string;
  beforeEach(() => { mkdirSync(parent, { recursive: true }); directory = mkdtempSync(join(parent, 'run-')); });
  afterEach(() => {
    jest.restoreAllMocks();
    if (!resolve(directory).startsWith(parent + sep)) throw new Error('cleanup escaped task directory');
    rmSync(directory, { recursive: true, force: true });
  });
  test('retains failed status while withholding original error from JSONL, stdout and rethrow', async () => {
    const sentinel = 'CONTROLLED_PRIVATE_SENTINEL_891';
    const original = Object.assign(new Error(`${sentinel} private witness value`), {
      name: sentinel, code: 'ENOMEM', cause: { token: sentinel }, privateKey: sentinel,
      stack: `${sentinel} at /private-controlled-fixture/witness.ts:1`,
    });
    const stdout = jest.spyOn(console, 'log').mockImplementation(() => {});
    const path = createPilotLog(directory, 'failure');
    const { phase } = createPilotReporter(path);
    let thrown: unknown;
    try { await phase('compile-membership', async () => { throw original; }); }
    catch (error) { thrown = error; }
    const jsonl = readFileSync(path, 'utf8');
    const printed = stdout.mock.calls.map((args) => args.join(' ')).join('\n');
    expect(jsonl).not.toContain(sentinel);
    expect(printed).not.toContain(sentinel);
    expect(inspect(thrown)).not.toContain(sentinel);
    const jestOutput = formatExecError(thrown as Error,
      { rootDir: resolve('.'), testMatch: ['**/*.test.ts'] }, { noStackTrace: false });
    expect(jestOutput).not.toContain(sentinel);
    expect(jestOutput).toContain('Actual-proof pilot phase failed');
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown).not.toBe(original);
    expect((thrown as Error & { cause?: unknown }).cause).toBeUndefined();
    const rows = jsonl.trim().split('\n').map((line) => JSON.parse(line));
    expect(rows.map((row) => row.status)).toEqual(['start', 'failed']);
    expect(rows[1]).toMatchObject({ phase: 'compile-membership', error: { name: 'Error', code: 'ENOMEM', stage: 'run' } });
    expect(printed.split('\n').map((line) => JSON.parse(line))).toEqual(rows);
  });
  test('preserves the successful result and complete event', async () => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    const path = createPilotLog(directory, 'success');
    const { phase } = createPilotReporter(path);
    expect(await phase('compile-membership', async () => 42)).toBe(42);
    const rows = readFileSync(path, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
    expect(rows.map((row) => row.status)).toEqual(['start', 'complete']);
    expect(rows[1].elapsedMs).toBeGreaterThanOrEqual(0);
  });
});
