import { resolve } from 'node:path';
import { runBatchSweep } from './experiments/batch-sweep.js';

try {
  const args = process.argv.slice(2);
  let outputDir = resolve('work', 'batch-sweep');
  let seed = 20261014;
  let smoke = false;
  let batchSizes: number[] | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--smoke') smoke = true;
    else if (args[i] === '--output' && args[i + 1]) outputDir = resolve(args[++i]);
    else if (args[i] === '--seed' && args[i + 1] && /^-?\d+$/.test(args[i + 1])) seed = Number(args[++i]);
    else if (args[i] === '--batches' && args[i + 1] && /^\d+(,\d+)*$/.test(args[i + 1])) batchSizes = args[++i].split(',').map(Number);
    else throw new Error('invalid batch-benchmark arguments');
  }
  await runBatchSweep({ outputDir, seed, smoke, batchSizes });
} catch {
  console.error('Batch benchmark did not complete successfully. Inspect retained run artifacts; only --output, --seed, --smoke and --batches are accepted.');
  process.exitCode = 1;
}
