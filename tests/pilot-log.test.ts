import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { createPilotLog } from './helpers/pilot-log.js';

describe('pilot log retention (filesystem only; no proof generation)', () => {
  const parent = resolve('work/task-2-log-tests');
  let directory: string;
  beforeEach(() => {
    mkdirSync(parent, { recursive: true });
    directory = mkdtempSync(join(parent, 'run-'));
  });
  afterEach(() => {
    const target = resolve(directory);
    if (!target.startsWith(parent + sep))
      throw new Error('test cleanup escaped task directory');
    rmSync(target, { recursive: true, force: true });
  });
  test('preserves the earlier failure when the same label is used twice', () => {
    const first = createPilotLog(directory, 'retry');
    appendFileSync(first, 'failed phase evidence\n');
    const second = createPilotLog(directory, 'retry');
    expect(readFileSync(first, 'utf8')).toBe('failed phase evidence\n');
    expect(second).not.toBe(first);
    expect(readFileSync(second, 'utf8')).toBe('');
  });
  test('fails exclusively on an existing run path without truncating it', () => {
    const first = createPilotLog(directory, 'retry', 'same-run');
    appendFileSync(first, 'preserved on collision\n');
    expect(() => createPilotLog(directory, 'retry', 'same-run')).toThrow(
      /EEXIST/
    );
    expect(readFileSync(first, 'utf8')).toBe('preserved on collision\n');
  });
  test.each([
    '../escape',
    '..\\escape',
    '/absolute',
    'C:\\escape',
    'a/b',
    '',
    '.',
    '..',
  ])('rejects unsafe label %p', (label) => {
    expect(() => createPilotLog(directory, label)).toThrow(/label/);
  });
  test('rejects an unsafe explicit run ID', () => {
    expect(() => createPilotLog(directory, 'retry', '../escape')).toThrow(
      /run ID/
    );
  });
});
