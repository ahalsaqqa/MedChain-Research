import { resolve } from 'node:path';
import { runHeightSweep } from './experiments/height-sweep.js';

try {
  const args = process.argv.slice(2);
  let outputDir = resolve('work', 'height-sweep');
  let seed = 20261014;
  let smoke = false;
  let heights: number[] | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--smoke') smoke = true;
    else if (args[i] === '--output' && args[i + 1]) outputDir = resolve(args[++i]);
    else if (args[i] === '--seed' && args[i + 1] && /^-?\d+$/.test(args[i + 1])) seed = Number(args[++i]);
    else if (args[i] === '--heights' && args[i + 1] && /^\d+(,\d+)*$/.test(args[i + 1])) heights = args[++i].split(',').map(Number);
    else throw new Error('invalid height-benchmark arguments');
  }
  await runHeightSweep({ outputDir, seed, smoke, heights });
} catch {
  console.error('Height benchmark did not complete successfully. Inspect retained run artifacts; only --output, --seed, --smoke and --heights are accepted.');
  process.exitCode = 1;
}
