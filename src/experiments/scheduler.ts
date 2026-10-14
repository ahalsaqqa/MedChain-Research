import { performance } from 'node:perf_hooks';
import { Observation, ObservationWriter, Operation, Phase, PublicParameters, sanitizeError, verificationSlots } from './observations.js';

export type Result<T> = { ok: true; value: T; row: Observation } | { ok: false; row: Observation };
export interface ObservationContext {
  writer: ObservationWriter; runId: string; treeHeight: number; reportable: boolean;
}
/** Operation clock and persistence boundary shared by the real runner's workloads. */
export async function measureOperation<T>(context: ObservationContext,
  operation: Operation, N: number, phase: Phase, attempt: number,
  fn: () => T | Promise<T>, count: number, parameters: PublicParameters = {},
  audit?: (value: T) => Partial<Pick<Observation, 'files' | 'bytes'>>): Promise<Result<T>> {
  const { writer, runId, treeHeight, reportable } = context;
  const start = { runId, operation, N, phase, attempt };
  writer.start(start);
  const started = performance.now();
  try {
    const value = await fn();
    const elapsed = performance.now() - started;
    const inventory = audit?.(value);
    const row: Observation = { ...start, status: 'success', elapsedMs: elapsed, recordsProcessed: count, ...inventory,
      publicParameters: { treeHeight, reportable, ...parameters } };
    writer.append(row);
    return { ok: true, value, row };
  } catch (error) {
    const row: Observation = { ...start, status: 'failure', elapsedMs: performance.now() - started, recordsProcessed: 0,
      error: sanitizeError(error, operation), publicParameters: { treeHeight, reportable, ...parameters } };
    writer.append(row);
    return { ok: false, row };
  }
}

export interface ProofSafety { unsafe: boolean }
export async function runProofWorkIfSafe(safety: ProofSafety, work: () => Promise<void>, skip: () => void): Promise<void> {
  if (safety.unsafe) skip();
  else await work();
}
export interface MembershipSchedule<T> {
  safety: ProofSafety; warmups: number; measured: number; verifications: number;
  prove: (phase: Phase, attempt: number) => Promise<Result<T>>;
  verify: (proof: T, phase: Phase, attempt: number, trial: number) => Promise<Result<unknown>>;
  skipProof: (phase: Phase, attempt: number) => Observation;
  skipVerification: (phase: Phase, attempt: number, trial: number) => void;
  append: (row: Observation) => void;
  onMeasuredProof: (proof: T) => void;
}
/** Pure scheduling around measured callbacks; it never substitutes proof implementations. */
export async function runMembershipTrials<T>(schedule: MembershipSchedule<T>): Promise<void> {
  const { safety } = schedule;
  const attempts = [
    ...Array.from({ length: schedule.warmups }, (_, i) => ({ phase: 'warmup' as const, attempt: i + 1 })),
    ...Array.from({ length: schedule.measured }, (_, i) => ({ phase: 'measured' as const, attempt: i + 1 })),
  ];
  for (const { phase, attempt } of attempts) {
    if (safety.unsafe) {
      verificationSlots(schedule.skipProof(phase, attempt), schedule.verifications).forEach(schedule.append);
      continue;
    }
    const result = await schedule.prove(phase, attempt);
    if (!result.ok) {
      safety.unsafe = true;
      verificationSlots(result.row, schedule.verifications).forEach(schedule.append);
      continue;
    }
    const verificationCount = phase === 'warmup' ? 1 : schedule.verifications;
    for (let trial = 1; trial <= verificationCount; trial++) {
      if (safety.unsafe) {
        schedule.skipVerification(phase, attempt, trial);
        continue;
      }
      const verified = await schedule.verify(result.value, phase, attempt, trial);
      if (!verified.ok) safety.unsafe = true;
    }
    if (phase === 'measured') schedule.onMeasuredProof(result.value);
  }
}
