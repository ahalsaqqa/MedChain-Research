import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { cpus, freemem, platform, release, totalmem } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { Cache, MerkleTree, setNumberOfWorkers } from 'o1js';
import { SYNTHETIC_GENERATOR_VERSION, syntheticRecords } from '../fixtures.js';
import { BatchQuery, membershipBatchProgram, requestedIdsHash } from '../membership-batch.js';
import { encodeRecord, encodedRecordCommitment, randomSalt } from '../records.js';
import { RECORD_CAPACITY, RECORD_TREE_HEIGHT, RecordWitness } from '../registry.js';
import { createRunDirectory, filesIn, PROOF_CACHE_PATH, provenance, REPOSITORY_ROOT } from './runner.js';

export type BatchSweepProtocol = {
  protocol: string; reportable: boolean; batchSizes: number[]; records: number;
  proofWarmups: number; proofMeasured: number; verifications: number;
};
export function batchSweepProtocol(smoke: boolean, batchSizes?: number[]): BatchSweepProtocol {
  if (smoke) return { protocol: 'batch-sweep-smoke', reportable: false, batchSizes: batchSizes ?? [1, 2], records: Math.max(8, ...(batchSizes ?? [1, 2])), proofWarmups: 0, proofMeasured: 1, verifications: 1 };
  return { protocol: 'batch-sweep-v1', reportable: true, batchSizes: batchSizes ?? [1, 4, 16, 64, 128, 256], records: 1000, proofWarmups: 1, proofMeasured: 10, verifications: 3 };
}
/** k distinct, evenly spread record indices (deterministic). */
export function batchIndices(batchSize: number, records: number): number[] {
  assert(batchSize >= 1 && batchSize <= records, 'batch must fit the dataset');
  return Array.from({ length: batchSize }, (_, j) => Math.floor((j * records) / batchSize));
}

type Row = {
  runId: string; operation: 'batch-compile' | 'batch-proof' | 'batch-verify'; batchSize: number;
  phase: 'warmup' | 'measured'; attempt: number; status: 'success' | 'failure' | 'skipped'; elapsedMs: number | null; error?: string;
};
const sha256 = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
const quantile = (xs: number[], q: number) => {
  const s = [...xs].sort((a, b) => a - b); const pos = (s.length - 1) * q; const lo = Math.floor(pos); const hi = Math.ceil(pos);
  return s[lo] + (s[hi] - s[lo]) * (pos - lo);
};

/** Same height-11 registry and records for every batch size; only records per proof change. Actual proofs. */
export async function runBatchSweep(options: { outputDir: string; seed: number; smoke?: boolean; batchSizes?: number[] }): Promise<void> {
  assert.notEqual(process.env.MEDCHAIN_REAL_PROOFS, 'false', 'actual proofs must be enabled');
  assert(Number.isSafeInteger(options.seed), 'seed must be a safe integer');
  const protocol = batchSweepProtocol(options.smoke === true, options.batchSizes);
  assert(protocol.records <= RECORD_CAPACITY, 'records must fit the height-11 registry');
  for (const k of protocol.batchSizes) assert(k <= protocol.records, `batch ${k} exceeds ${protocol.records} records`);
  const sdk = JSON.parse(readFileSync(join(REPOSITORY_ROOT, 'node_modules', 'o1js', 'package.json'), 'utf8')).version;
  assert.equal(sdk, '2.2.0', 'benchmark requires pinned o1js');
  const { runId, directory } = createRunDirectory(resolve(options.outputDir));
  const rows: Row[] = [];
  const log = (row: Row) => { rows.push(row); appendFileSync(join(directory, 'observations.jsonl'), JSON.stringify(row) + '\n', { flag: 'a' }); };
  const metadata = {
    runId, createdAt: new Date().toISOString(), completedAt: null as string | null, outcome: 'running',
    ...protocol, treeHeight: RECORD_TREE_HEIGHT, seed: options.seed, generatorVersion: SYNTHETIC_GENERATOR_VERSION,
    source: provenance(), dependencyLockHash: sha256(readFileSync(join(REPOSITORY_ROOT, 'package-lock.json'))),
    node: process.version, o1js: sdk, os: { platform: platform(), release: release(), architecture: process.arch },
    cpu: { model: cpus()[0]?.model ?? 'unavailable', logicalCpus: cpus().length },
    memory: { totalBytes: totalmem(), availableAtStartBytes: freemem(), availableAtEndBytes: null as number | null },
    proofMode: 'real', proofsEnabled: true, workers: 1, provingProcesses: 1,
    cache: { relativePath: 'work/proof-cache', filesBefore: filesIn(PROOF_CACHE_PATH).length, filesAfter: null as number | null },
    circuits: [] as { batchSize: number; rows: number; digest: string }[],
    clockBoundaries: {
      clock: 'performance.now() monotonic milliseconds; JSONL writes outside the clock',
      compile: 'program.compile with the SDK filesystem cache, one per batch size; includes key generation when the cache is empty',
      proof: 'program.proveBatch only; prepared query, k encoded records, salts and height-11 witnesses at evenly spread indices',
      verify: 'program.verify plus comparison of the public root and requested-ID list hash with values recomputed from the expected IDs',
      tree: 'tree construction, witness extraction and list hashing for the query are outside every clock',
    },
    scope: 'Synthetic records in one height-11 registry; only records per proof change; one proving process; no throughput claim beyond these timings',
    summaries: [] as unknown[],
  };
  const save = () => writeFileSync(join(directory, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n');
  save();
  setNumberOfWorkers(1);
  const cache = Cache.FileSystem(PROOF_CACHE_PATH);
  const records = syntheticRecords(protocol.records, options.seed);
  const encoded = records.map(encodeRecord);
  const salts = records.map(() => randomSalt()); // in-process only; never written
  const tree = new MerkleTree(RECORD_TREE_HEIGHT);
  encoded.forEach((e, i) => tree.setLeaf(BigInt(i), encodedRecordCommitment(e, salts[i])));
  const root = tree.getRoot();
  const timed = async <T>(fn: () => Promise<T>) => { const t0 = performance.now(); const value = await fn(); return { value, ms: performance.now() - t0 }; };

  for (const k of protocol.batchSizes) {
    const { program } = membershipBatchProgram(k);
    const analysis = (await program.analyzeMethods()).proveBatch;
    metadata.circuits.push({ batchSize: k, rows: analysis.rows, digest: analysis.digest });
    save();
    const idx = batchIndices(k, protocol.records);
    const batchRecords = idx.map((i) => encoded[i]);
    const batchSalts = idx.map((i) => salts[i]);
    const batchWitnesses = idx.map((i) => new RecordWitness(tree.getWitness(BigInt(i))));
    const expectedHash = requestedIdsHash(batchRecords.map((r) => r.recordIdHash));
    const query = new BatchQuery({ root, requestedIdsHash: expectedHash });

    let ok = true;
    try {
      const c = await timed(() => program.compile({ cache, proofsEnabled: true }));
      log({ runId, operation: 'batch-compile', batchSize: k, phase: 'measured', attempt: 1, status: 'success', elapsedMs: c.ms });
    } catch (e) {
      ok = false; log({ runId, operation: 'batch-compile', batchSize: k, phase: 'measured', attempt: 1, status: 'failure', elapsedMs: null, error: (e as Error)?.name ?? 'Error' });
    }
    const slots = [
      ...Array.from({ length: protocol.proofWarmups }, (_, i) => ({ phase: 'warmup' as const, attempt: i + 1 })),
      ...Array.from({ length: protocol.proofMeasured }, (_, i) => ({ phase: 'measured' as const, attempt: i + 1 })),
    ];
    for (const { phase, attempt } of slots) {
      if (!ok) {
        if (phase === 'measured') log({ runId, operation: 'batch-proof', batchSize: k, phase, attempt, status: 'skipped', elapsedMs: null });
        continue;
      }
      try {
        const p = await timed(() => program.proveBatch(query, batchRecords, batchSalts, batchWitnesses));
        log({ runId, operation: 'batch-proof', batchSize: k, phase, attempt, status: 'success', elapsedMs: p.ms });
        const verifications = phase === 'warmup' ? 1 : protocol.verifications;
        for (let v = 1; v <= verifications; v++) {
          const r = await timed(async () => {
            assert.equal(await program.verify(p.value.proof), true);
            assert.equal(p.value.proof.publicInput.root.toString(), root.toString());
            assert.equal(p.value.proof.publicInput.requestedIdsHash.toString(), expectedHash.toString());
          });
          log({ runId, operation: 'batch-verify', batchSize: k, phase, attempt: (attempt - 1) * verifications + v, status: 'success', elapsedMs: r.ms });
        }
      } catch (e) {
        ok = false; log({ runId, operation: 'batch-proof', batchSize: k, phase, attempt, status: 'failure', elapsedMs: null, error: (e as Error)?.name ?? 'Error' });
      }
    }
  }

  const groups = new Map<string, number[]>();
  for (const r of rows) if (r.phase === 'measured' && r.status === 'success') {
    const key = `${r.operation}|${r.batchSize}`; groups.set(key, [...(groups.get(key) ?? []), r.elapsedMs!]);
  }
  metadata.summaries = [...groups].map(([key, xs]) => {
    const [operation, k] = key.split('|'); const batchSize = Number(k); const med = quantile(xs, 0.5);
    return { operation, batchSize, n: xs.length, minMs: Math.min(...xs), medianMs: med, maxMs: Math.max(...xs),
      q1Ms: quantile(xs, 0.25), q3Ms: quantile(xs, 0.75), medianPerRecordMs: med / batchSize };
  });
  writeFileSync(join(directory, 'summaries.json'), JSON.stringify(metadata.summaries, null, 2) + '\n');
  metadata.outcome = rows.every((r) => r.status === 'success') ? 'completed' : 'completed-with-failures-or-skips';
  metadata.completedAt = new Date().toISOString();
  metadata.memory.availableAtEndBytes = freemem();
  metadata.cache.filesAfter = existsSync(PROOF_CACHE_PATH) ? filesIn(PROOF_CACHE_PATH).length : 0;
  save();
  console.log(JSON.stringify({ runId, outcome: metadata.outcome, circuits: metadata.circuits.map(({ batchSize, rows }) => ({ batchSize, rows })) }));
}
