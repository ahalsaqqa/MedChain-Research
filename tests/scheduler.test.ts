import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Observation, ObservationWriter, Operation, Phase, PublicParameters } from '../src/experiments/observations.js';
import { measureOperation, runMembershipTrials, runProofWorkIfSafe } from '../src/experiments/scheduler.js';

describe('heavy proof scheduler (controlled callbacks; no cryptographic proving)', () => {
  // Would fail if a failed Result were ignored, a skipped slot were renumbered, or
  // the unsafe state were reset before later proofs/datasets/root-update work.
  it.each(['measured', 'warmup'] as const)('aborts heavy work after an ENOMEM rejection in %s verification', async (failedPhase) => {
    const directory = await mkdtemp(join(tmpdir(), 'medchain-scheduler-'));
    try {
      const writer = new ObservationWriter(directory);
      const context = { writer, runId: 'controlled', treeHeight: 11, reportable: false };
      const safety = { unsafe: false };
      const invoked: string[] = [];
      const skipped = (operation: Operation, N: number, phase: Phase, attempt: number, parameters: PublicParameters = {}) => {
        const row: Observation = { runId: 'controlled', operation, N, phase, attempt, status: 'skipped',
          elapsedMs: null, recordsProcessed: 0, publicParameters: { treeHeight: 11, reportable: false, abortReason: 'proof-failure', ...parameters } };
        writer.append(row); return row;
      };
      const failAt = failedPhase === 'measured' ? 4 : 1;
      for (const N of [100, 500]) {
        // The same production gate guards the real runner's next registry update.
        if (N === 500) await runProofWorkIfSafe(safety, async () => {
          invoked.push('later-registry-prover');
        }, () => { skipped('registry-update-proof', N, 'measured', 1); });
        await runMembershipTrials({
          safety, warmups: 1, measured: 5, verifications: 10,
          prove: (phase, attempt) => measureOperation(context, 'membership-proof', N, phase, attempt, async () => {
            invoked.push(`prove/${N}/${phase}/${attempt}`);
            return 'controlled-public-placeholder';
          }, 1, { selectedIndex: N / 2 }),
          verify: (_proof, phase, attempt, trial) => measureOperation(context, 'membership-verify', N, phase,
            phase === 'warmup' ? trial : (attempt - 1) * 10 + trial, async () => {
              invoked.push(`verify/${N}/${phase}/${attempt}/${trial}`);
              if (N === 100 && phase === failedPhase && attempt === 1 && trial === failAt)
                throw Object.assign(new Error('PRIVATE witness must not enter evidence'), { code: 'ENOMEM' });
            }, 1, { proofAttempt: attempt, selectedIndex: N / 2 }),
          skipProof: (phase, attempt) => skipped('membership-proof', N, phase, attempt, { selectedIndex: N / 2 }),
          skipVerification: (phase, attempt, trial) => {
            skipped('membership-verify', N, phase, phase === 'warmup' ? trial : (attempt - 1) * 10 + trial,
              { proofAttempt: attempt, selectedIndex: N / 2 });
          },
          append: (row) => writer.append(row), onMeasuredProof: () => {},
        });
        // Retain lightweight work after the conservative heavy-work abort.
        await measureOperation(context, 'validation', N, 'measured', 1, () => 1, N);
      }
      expect(safety.unsafe).toBe(true);
      const failures = writer.rows.filter((row) => row.status === 'failure');
      expect(failures).toHaveLength(1);
      expect(failures[0]).toMatchObject({ operation: 'membership-verify', N: 100, phase: failedPhase, attempt: failAt,
        recordsProcessed: 0, error: { name: 'Error', code: 'ENOMEM', stage: 'membership-verify' } });
      expect(failures[0].elapsedMs).toBeGreaterThanOrEqual(0);
      expect(invoked).toEqual(failedPhase === 'measured' ? [
        'prove/100/warmup/1', 'verify/100/warmup/1/1', 'prove/100/measured/1',
        'verify/100/measured/1/1', 'verify/100/measured/1/2', 'verify/100/measured/1/3', 'verify/100/measured/1/4',
      ] : ['prove/100/warmup/1', 'verify/100/warmup/1/1']);
      for (const N of [100, 500]) {
        const measured = writer.rows.filter((row) => row.operation === 'membership-verify' && row.N === N && row.phase === 'measured');
        expect(measured.map((row) => row.attempt)).toEqual(Array.from({ length: 50 }, (_, i) => i + 1));
        const beforeFailure = N === 100 && failedPhase === 'measured' ? 3 : 0;
        const failureCount = N === 100 && failedPhase === 'measured' ? 1 : 0;
        expect(measured.filter((row) => row.status === 'success')).toHaveLength(beforeFailure);
        expect(measured.filter((row) => row.status === 'skipped')).toHaveLength(50 - beforeFailure - failureCount);
      }
      expect(writer.rows.filter((row) => row.operation === 'registry-update-proof')).toEqual([
        expect.objectContaining({ N: 500, status: 'skipped', elapsedMs: null }),
      ]);
      const allSkipped = writer.rows.filter((row) => row.status === 'skipped');
      expect(allSkipped.every((row) => row.elapsedMs === null && row.recordsProcessed === 0 && row.publicParameters.abortReason === 'proof-failure')).toBe(true);
      expect(writer.rows.filter((row) => row.operation === 'validation' && row.status === 'success')).toHaveLength(2);
      writer.finalize();
      expect(await readFile(join(directory, 'observations.jsonl'), 'utf8')).not.toContain('PRIVATE');
      const events = (await readFile(join(directory, 'events.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line));
      expect(events.filter((row) => row.operation === 'membership-verify')).toHaveLength(failedPhase === 'measured' ? 5 : 1);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});
