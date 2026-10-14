import { appendFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { sanitizeError } from '../../src/experiments/observations.js';

/** The actual pilot's two public sinks and phase boundary, shared with bounded failure tests. */
export function createPilotReporter(logPath: string) {
  const event = (data: object) => {
    const row = { at: new Date().toISOString(), ...data, memory: process.memoryUsage() };
    appendFileSync(logPath, `${JSON.stringify(row)}\n`);
    console.log(JSON.stringify(row));
  };
  async function phase<T>(name: string, operation: () => Promise<T>): Promise<T> {
    event({ phase: name, status: 'start' });
    const start = performance.now();
    try {
      const result = await operation();
      event({ phase: name, status: 'complete', elapsedMs: performance.now() - start });
      return result;
    } catch (error) {
      event({ phase: name, status: 'failed', elapsedMs: performance.now() - start,
        error: sanitizeError(error, 'run') });
      // Jest is a public error sink too: never carry the original message, stack,
      // cause or custom properties beyond this boundary.
      throw new Error('Actual-proof pilot phase failed; inspect sanitized phase events');
    }
  }
  return { event, phase };
}
