import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  Observation, ObservationWriter, sanitizeError, summarize, verificationSlots,
} from '../src/experiments/observations.js';
import { createRunDirectory, createScratchDirectory, protocolFor } from '../src/experiments/runner.js';

const row = (changes: Partial<Observation> = {}): Observation => ({
  runId: 'fixture', operation: 'membership-proof', N: 100, phase: 'measured',
  attempt: 1, status: 'success', elapsedMs: 2, recordsProcessed: 1,
  publicParameters: { treeHeight: 11, selectedIndex: 50, reportable: true }, ...changes,
});

describe('retained experiment observations', () => {
  it('keeps reduced smoke data explicitly nonreportable and full slots exact', () => {
    expect(protocolFor(false)).toEqual({
      protocol: 'reportable-v1', reportable: true, sizes: [100, 500, 1000],
      hostWarmups: 1, hostMeasured: 5, cryptoWarmups: 5, cryptoMeasured: 30,
      proofWarmups: 1, proofMeasured: 5, verifications: 10,
    });
    expect(protocolFor(true)).toMatchObject({ protocol: 'smoke', reportable: false, sizes: [3], cryptoMeasured: 2, proofMeasured: 1 });
  });

  it('reserves independent run children without overwriting earlier evidence', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'medchain-run-'));
    try {
      const first = createRunDirectory(parent);
      const second = createRunDirectory(parent);
      expect(first.runId).not.toBe(second.runId);
      expect(first.directory).toBe(join(parent, first.runId));
      expect(second.directory).toBe(join(parent, second.runId));
    } finally { await rm(parent, { recursive: true, force: true }); }
  });

  it('sets up scratch for successive datasets without deleting earlier contents', async () => {
    const run = await mkdtemp(join(tmpdir(), 'medchain-scratch-'));
    try {
      const firstDatasetScratch = createScratchDirectory(run);
      await writeFile(join(firstDatasetScratch, 'retained-marker'), 'prior dataset');
      const secondDatasetScratch = createScratchDirectory(run);
      expect(secondDatasetScratch).toBe(firstDatasetScratch);
      expect(await readFile(join(secondDatasetScratch, 'retained-marker'), 'utf8')).toBe('prior dataset');
    } finally { await rm(run, { recursive: true, force: true }); }
  });
  // Catches including failed durations, counting skipped work as attempted, or warmups.
  it('counts measured work and computes only success durations', () => {
    const rows = [row(), row({ attempt: 2, elapsedMs: 8 }),
      row({ attempt: 3, status: 'failure', elapsedMs: 1000, recordsProcessed: 0 }),
      row({ phase: 'warmup', elapsedMs: 999 }),
      ...Array.from({ length: 10 }, (_, i) => row({ attempt: i + 4, status: 'skipped', elapsedMs: null, recordsProcessed: 0 }))];
    expect(summarize(rows)).toEqual([{
      operation: 'membership-proof', N: 100, attempted: 3, succeeded: 2, failed: 1,
      skipped: 10, minMs: 2, medianMs: 5, maxMs: 8,
    }]);
  });

  it('reports null timings when every trial failed or was skipped', () => {
    expect(summarize([row({ status: 'failure', elapsedMs: 19 }), row({ status: 'skipped', elapsedMs: null })])[0])
      .toMatchObject({ attempted: 1, succeeded: 0, failed: 1, skipped: 1, minMs: null, medianMs: null, maxMs: null });
  });

  it('rejects combining smoke and reportable rows in one measured summary', () => {
    expect(() => summarize([row(), row({ publicParameters: { reportable: false } })])).toThrow(/smoke/);
  });

  // Catches manufacturing successful verifications after unavailable proving output.
  it('gives a failed measured proof ten skipped verification slots', () => {
    const failed = row({ status: 'failure', recordsProcessed: 0,
      error: sanitizeError(new Error('secret salt and witness'), 'membership-proof') });
    const slots = verificationSlots(failed);
    expect(slots).toHaveLength(10);
    expect(slots.every((entry) => entry.operation === 'membership-verify' && entry.status === 'skipped' && entry.elapsedMs === null)).toBe(true);
    expect(summarize(slots)[0]).toMatchObject({ attempted: 0, succeeded: 0, failed: 0, skipped: 10, medianMs: null });
    expect(verificationSlots(row())).toEqual([]);
    expect(verificationSlots(row({ phase: 'warmup', status: 'failure' }))).toEqual([]);
  });

  // Catches any raw SDK message, custom name, stack, or arbitrary context leaking.
  it('allows only fixed error categories and known codes', () => {
    const error = Object.assign(new Error('SECRET_KEY=private\n"salt",witness'), {
      name: 'private name', code: 'ENOMEM', salt: 'private', privateKey: 'private',
    });
    expect(sanitizeError(error, 'membership-proof')).toEqual({ name: 'Error', code: 'ENOMEM', stage: 'membership-proof' });
    expect(JSON.stringify(sanitizeError({ name: 'SECRET', code: 'SECRET' }, 'storage-write'))).not.toContain('SECRET');
  });

  it('durably retains completed rows and starts, exports JSON and escaped CSV, and refuses secrets', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'medchain-observations-'));
    try {
      const writer = new ObservationWriter(directory);
      const failed = row({ status: 'failure', error: sanitizeError(Object.assign(new Error('PRIVATE'), { code: 'ENOMEM' }), 'membership-proof') });
      writer.start({ runId: 'fixture', operation: 'membership-proof', N: 100, phase: 'measured', attempt: 1 });
      writer.append(failed);
      expect(JSON.parse((await readFile(join(directory, 'observations.jsonl'), 'utf8')).trim())).toEqual(failed);
      expect(JSON.parse((await readFile(join(directory, 'events.jsonl'), 'utf8')).trim())).toMatchObject({ event: 'start', operation: 'membership-proof', attempt: 1 });
      expect(() => writer.append(row({ publicParameters: { salt: 'PRIVATE' } as never }))).toThrow(/public parameter/);
      expect(() => writer.append({ ...row(), privateKey: 'PRIVATE' } as never)).toThrow(/observation field/);
      expect(() => writer.append(row({ error: { name: 'Error', stage: 'membership-proof', message: 'PRIVATE' } as never }))).toThrow(/error/);
      writer.finalize();
      expect(JSON.parse(await readFile(join(directory, 'observations.json'), 'utf8'))).toEqual([failed]);
      expect(await readFile(join(directory, 'observations.csv'), 'utf8')).toContain('"{""name"":""Error"",""code"":""ENOMEM"",""stage"":""membership-proof""}"');
      expect(await readFile(join(directory, 'observations.csv'), 'utf8')).not.toContain('PRIVATE');
      expect(JSON.parse(await readFile(join(directory, 'summaries.json'), 'utf8'))).toEqual(summarize([failed]));
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});
