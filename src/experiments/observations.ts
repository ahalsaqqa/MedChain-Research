import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export type Phase = 'warmup' | 'measured' | 'setup';
export type Status = 'success' | 'failure' | 'skipped';
export type Operation = 'validation' | 'encoding' | 'commitments' | 'tree' |
  'aes-encrypt' | 'aes-decrypt' | 'storage-write' | 'storage-read' |
  'compile-membership' | 'compile-registry' | 'registry-deployment' |
  'registry-update-prepare' | 'registry-update-proof' | 'registry-update-finalize' |
  'membership-proof' | 'membership-verify' | 'run';
export interface PublicParameters {
  treeHeight?: number; selectedIndex?: number; reportable?: boolean;
  cacheAffected?: boolean; proofAttempt?: number; abortReason?: 'proof-failure' | 'setup-failure';
  boundary?: string;
}
export interface PublicError { name: string; code?: string; stage: Operation }
export interface Observation {
  runId: string; operation: Operation; N: number; phase: Phase; attempt: number;
  status: Status; elapsedMs: number | null; recordsProcessed: number;
  files?: number; bytes?: number; error?: PublicError; publicParameters: PublicParameters;
}
export interface Summary {
  operation: Operation; N: number; attempted: number; succeeded: number;
  failed: number; skipped: number; minMs: number | null; medianMs: number | null; maxMs: number | null;
}
export type Start = Pick<Observation, 'runId' | 'operation' | 'N' | 'phase' | 'attempt'>;
export function summarize(rows: readonly Observation[]): Summary[] {
  if (new Set(rows.map((row) => row.publicParameters.reportable).filter((value) => value !== undefined)).size > 1)
    throw new Error('cannot mix smoke and reportable observations');
  const groups = new Map<string, Observation[]>();
  for (const row of rows) {
    if (row.phase !== 'measured') continue;
    const key = `${row.operation}/${row.N}`;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  return Array.from(groups.values(), (group) => {
    const durations = group.filter((r) => r.status === 'success' && r.elapsedMs !== null)
      .map((r) => r.elapsedMs!).sort((a, b) => a - b);
    const middle = Math.floor(durations.length / 2);
    return {
      operation: group[0].operation, N: group[0].N,
      attempted: group.filter((r) => r.status !== 'skipped').length,
      succeeded: group.filter((r) => r.status === 'success').length,
      failed: group.filter((r) => r.status === 'failure').length,
      skipped: group.filter((r) => r.status === 'skipped').length,
      minMs: durations[0] ?? null,
      medianMs: durations.length === 0 ? null : durations.length % 2 ? durations[middle] : (durations[middle - 1] + durations[middle]) / 2,
      maxMs: durations[durations.length - 1] ?? null,
    };
  });
}
const OPERATIONS: readonly Operation[] = ['validation', 'encoding', 'commitments', 'tree',
  'aes-encrypt', 'aes-decrypt', 'storage-write', 'storage-read', 'compile-membership',
  'compile-registry', 'registry-deployment', 'registry-update-prepare',
  'registry-update-proof', 'registry-update-finalize', 'membership-proof', 'membership-verify', 'run'];
const ERROR_NAMES = ['Error', 'TypeError', 'RangeError', 'SyntaxError', 'UnknownError'];
const ERROR_CODES = ['ENOMEM', 'ENOSPC', 'ENOENT', 'EACCES', 'EPERM', 'EIO', 'EMFILE', 'ERR_OUT_OF_RANGE', 'ERR_ASSERTION'];

/** SDK messages/stacks can contain private inputs: never serialize them. */
export function sanitizeError(error: unknown, stage: Operation): PublicError {
  if (!OPERATIONS.includes(stage)) throw new Error('invalid error stage');
  const name = error instanceof TypeError ? 'TypeError' : error instanceof RangeError ? 'RangeError' :
    error instanceof SyntaxError ? 'SyntaxError' : error instanceof Error ? 'Error' : 'UnknownError';
  const code = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code')?.value : undefined;
  return { name, ...(ERROR_CODES.includes(code) ? { code } : {}), stage };
}

/** Missing proof output means no verification was attempted. */
export function verificationSlots(proof: Observation, count = 10): Observation[] {
  if (proof.phase !== 'measured' || proof.status === 'success') return [];
  return Array.from({ length: count }, (_, index) => ({
    runId: proof.runId, operation: 'membership-verify', N: proof.N,
    phase: 'measured', attempt: (proof.attempt - 1) * count + index + 1,
    status: 'skipped', elapsedMs: null, recordsProcessed: 0,
    publicParameters: { ...proof.publicParameters, proofAttempt: proof.attempt, abortReason: 'proof-failure' },
  }));
}
function exactFields(value: object, keys: readonly string[], label: string) {
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !keys.includes(key) || !('value' in Object.getOwnPropertyDescriptor(value, key)!))
      throw new Error(`invalid ${label} field`);
  }
}
function validate(row: Observation): void {
  exactFields(row, ['runId', 'operation', 'N', 'phase', 'attempt', 'status', 'elapsedMs', 'recordsProcessed', 'files', 'bytes', 'error', 'publicParameters'], 'observation');
  if (!OPERATIONS.includes(row.operation) || !['warmup', 'measured', 'setup'].includes(row.phase) ||
    !['success', 'failure', 'skipped'].includes(row.status) || !/^[A-Za-z0-9_-]{1,64}$/.test(row.runId)) throw new Error('invalid observation');
  for (const n of [row.N, row.attempt, row.recordsProcessed, row.files ?? 0, row.bytes ?? 0])
    if (!Number.isSafeInteger(n) || n < 0) throw new Error('invalid observation count');
  if (row.status === 'skipped' ? row.elapsedMs !== null : typeof row.elapsedMs !== 'number' || !Number.isFinite(row.elapsedMs) || row.elapsedMs < 0)
    throw new Error('invalid observation duration');
  exactFields(row.publicParameters, ['treeHeight', 'selectedIndex', 'reportable', 'cacheAffected', 'proofAttempt', 'abortReason', 'boundary'], 'public parameter');
  for (const [key, value] of Object.entries(row.publicParameters)) {
    const valid = ['treeHeight', 'selectedIndex', 'proofAttempt'].includes(key) ? Number.isSafeInteger(value) && (value as number) >= 0 :
      ['reportable', 'cacheAffected'].includes(key) ? typeof value === 'boolean' : key === 'abortReason' ?
        ['proof-failure', 'setup-failure'].includes(value as string) : (BOUNDARIES as readonly string[]).includes(value as string);
    if (!valid) throw new Error('invalid public parameter value');
  }
  if (row.error) {
    exactFields(row.error, ['name', 'code', 'stage'], 'error');
    if (!ERROR_NAMES.includes(row.error.name) || !OPERATIONS.includes(row.error.stage) ||
      (row.error.code !== undefined && !ERROR_CODES.includes(row.error.code))) throw new Error('invalid error context');
  }
}
export const BOUNDARIES = [
  'host-validation', 'encoding-includes-validation', 'preencoded-commitments', 'precomputed-tree',
  'aes-only-prepared-inputs', 'prepared-envelope-storage', 'warm-content-read',
  'sdk-cache-compilation', 'signed-local-deployment', 'local-update-prepare',
  'transaction-prove-only', 'local-update-finalize', 'prepared-membership-prove', 'cryptographic-and-anchor-verify',
] as const;
function csv(objects: readonly object[], headers: readonly string[]): string {
  const cell = (value: unknown) => value === undefined || value === null ? '' :
    `"${(typeof value === 'object' ? JSON.stringify(value) : String(value)).replaceAll('"', '""')}"`;
  return headers.join(',') + '\n' + objects.map((row) => headers.map((key) => cell((row as Record<string, unknown>)[key])).join(',')).join('\n') + '\n';
}
export class ObservationWriter {
  readonly rows: Observation[] = [];
  constructor(readonly directory: string) {
    writeFileSync(join(directory, 'observations.jsonl'), '', { flag: 'wx' });
    writeFileSync(join(directory, 'events.jsonl'), '', { flag: 'wx' });
  }
  start(start: Start): void {
    exactFields(start, ['runId', 'operation', 'N', 'phase', 'attempt'], 'start');
    validate({ ...start, status: 'skipped', elapsedMs: null, recordsProcessed: 0, publicParameters: {} });
    appendFileSync(join(this.directory, 'events.jsonl'), JSON.stringify({ event: 'start', at: new Date().toISOString(), ...start }) + '\n', { flush: true });
  }
  append(row: Observation): void {
    validate(row);
    const serialized = JSON.stringify(row);
    appendFileSync(join(this.directory, 'observations.jsonl'), serialized + '\n', { flush: true });
    this.rows.push(JSON.parse(serialized) as Observation);
  }
  finalize(): void {
    const raw = readFileSync(join(this.directory, 'observations.jsonl'), 'utf8').trim();
    const retained: Observation[] = raw ? raw.split('\n').map((line) => JSON.parse(line)) : [];
    const summaries = summarize(retained);
    if (JSON.stringify(summaries) !== JSON.stringify(summarize(this.rows))) throw new Error('retained summary mismatch');
    writeFileSync(join(this.directory, 'observations.json'), JSON.stringify(retained, null, 2) + '\n');
    writeFileSync(join(this.directory, 'observations.csv'), csv(retained, ['runId', 'operation', 'N', 'phase', 'attempt', 'status', 'elapsedMs', 'recordsProcessed', 'files', 'bytes', 'error', 'publicParameters']));
    writeFileSync(join(this.directory, 'summaries.json'), JSON.stringify(summaries, null, 2) + '\n');
    writeFileSync(join(this.directory, 'summaries.csv'), csv(summaries, ['operation', 'N', 'attempted', 'succeeded', 'failed', 'skipped', 'minMs', 'medianMs', 'maxMs']));
  }
}
