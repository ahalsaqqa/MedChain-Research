import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** Reserve a new diagnostic log; a repeated label never reuses earlier evidence. */
export function createPilotLog(
  directory: string,
  label = 'latest',
  runId: string = randomUUID()
): string {
  const safeToken = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
  if (!safeToken.test(label))
    throw new Error(
      'pilot label must be a safe filename token (1-64 characters)'
    );
  if (!safeToken.test(runId))
    throw new Error(
      'pilot run ID must be a safe filename token (1-64 characters)'
    );
  mkdirSync(directory, { recursive: true });
  const path = join(directory, `pilot-${label}-${runId}.jsonl`);
  writeFileSync(path, '', { flag: 'wx' });
  return path;
}
