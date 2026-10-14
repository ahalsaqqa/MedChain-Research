import { resolve } from 'node:path';
import { runExperiments } from './experiments/runner.js';

try {
  const args = process.argv.slice(2);
  let outputDir = resolve('work', 'benchmarks');
  let seed = 20261014;
  let smoke = false;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--smoke') smoke = true;
    else if (args[i] === '--output' && args[i + 1]) outputDir = resolve(args[++i]);
    else if (args[i] === '--seed' && args[i + 1] && /^-?\d+$/.test(args[i + 1])) seed = Number(args[++i]);
    else throw new Error('invalid benchmark arguments');
  }
  await runExperiments({ outputDir, seed, proofMode: 'real', smoke });
} catch {
  // All SDK failures are retained through the allowlisted observation error schema.
  console.error('Benchmark did not complete successfully. Inspect retained sanitized run artifacts; only --output, --seed and --smoke are accepted.');
  process.exitCode = 1;
}
