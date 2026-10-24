import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { cpus, freemem, platform, release, totalmem } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { Cache, MerkleTree, setNumberOfWorkers } from 'o1js';
import { SYNTHETIC_GENERATOR_VERSION, syntheticRecords } from '../fixtures.js';
import { membershipProgramForHeight } from '../membership-height.js';
import { MembershipQuery } from '../membership.js';
import { encodeRecord, encodedRecordCommitment, hashIdentifier, randomSalt } from '../records.js';
import { createRunDirectory, filesIn, PROOF_CACHE_PATH, provenance, REPOSITORY_ROOT } from './runner.js';

export type HeightSweepProtocol = {
  protocol: string; reportable: boolean; heights: number[]; records: number;
  proofWarmups: number; proofMeasured: number; verifications: number;
};
export function heightSweepProtocol(smoke: boolean, heights?: number[]): HeightSweepProtocol {
  if (smoke) return { protocol: 'height-sweep-smoke', reportable: false, heights: heights ?? [11, 12], records: 8, proofWarmups: 0, proofMeasured: 1, verifications: 1 };
  return { protocol: 'height-sweep-v1', reportable: true, heights: heights ?? [11, 16, 20, 24, 32, 64, 128], records: 1000, proofWarmups: 1, proofMeasured: 10, verifications: 3 };
}

type Row = {
  runId: string; operation: 'height-compile' | 'height-proof' | 'height-verify'; treeHeight: number;
  phase: 'warmup' | 'measured'; attempt: number; status: 'success' | 'failure' | 'skipped'; elapsedMs: number | null;
  error?: string;
};
const sha256 = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
const quantile = (xs: number[], q: number) => {
  const s = [...xs].sort((a, b) => a - b); const pos = (s.length - 1) * q; const lo = Math.floor(pos); const hi = Math.ceil(pos);
  return s[lo] + (s[hi] - s[lo]) * (pos - lo);
};

/** Same records at every height; only tree height (path length) changes. Always actual proofs. */
export async function runHeightSweep(options: { outputDir: string; seed: number; smoke?: boolean; heights?: number[] }): Promise<void> {
  assert.notEqual(process.env.MEDCHAIN_REAL_PROOFS, 'false', 'actual proofs must be enabled');
  assert(Number.isSafeInteger(options.seed), 'seed must be a safe integer');
  const protocol = heightSweepProtocol(options.smoke === true, options.heights);
  for (const h of protocol.heights) assert(2 ** (h - 1) >= protocol.records, `height ${h} holds 2^(h-1) leaves, fewer than ${protocol.records} records`);
  const sdk = JSON.parse(readFileSync(join(REPOSITORY_ROOT, 'node_modules', 'o1js', 'package.json'), 'utf8')).version;
  assert.equal(sdk, '2.2.0', 'benchmark requires pinned o1js');
  const { runId, directory } = createRunDirectory(resolve(options.outputDir));
  const rows: Row[] = [];
  const log = (row: Row) => { rows.push(row); appendFileSync(join(directory, 'observations.jsonl'), JSON.stringify(row) + '\n', { flag: 'a' }); };
  const metadata = {
    runId, createdAt: new Date().toISOString(), completedAt: null as string | null, outcome: 'running',
    ...protocol, seed: options.seed, generatorVersion: SYNTHETIC_GENERATOR_VERSION,
    source: provenance(), dependencyLockHash: sha256(readFileSync(join(REPOSITORY_ROOT, 'package-lock.json'))),
    node: process.version, o1js: sdk, os: { platform: platform(), release: release(), architecture: process.arch },
    cpu: { model: cpus()[0]?.model ?? 'unavailable', logicalCpus: cpus().length },
    memory: { totalBytes: totalmem(), availableAtStartBytes: freemem(), availableAtEndBytes: null as number | null },
    proofMode: 'real', proofsEnabled: true, workers: 1, provingProcesses: 1,
    cache: { relativePath: 'work/proof-cache', filesBefore: filesIn(PROOF_CACHE_PATH).length, filesAfter: null as number | null },
    circuits: [] as { treeHeight: number; capacity: string; witnessPathLength: number; rows: number; digest: string }[],
    clockBoundaries: {
      clock: 'performance.now() monotonic milliseconds; JSONL writes outside the clock',
      compile: 'program.compile with the SDK filesystem cache, one per height; includes key generation when the cache is empty',
      proof: 'program.proveRecord only, prepared query, encoded record, salt and witness for record index floor(records/2)',
      verify: 'program.verify plus comparison of public root and requested-ID hash with the prepared expectations',
      tree: 'tree construction and witness extraction are outside every clock',
    },
    scope: 'Synthetic records; the same records at every height so only Merkle path length changes; one proving process; no throughput claim',
    summaries: [] as unknown[],
  };
  const save = () => writeFileSync(join(directory, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n');
  save();
  setNumberOfWorkers(1);
  const cache = Cache.FileSystem(PROOF_CACHE_PATH);
  const records = syntheticRecords(protocol.records, options.seed);
  const encoded = records.map(encodeRecord);
  const salts = records.map(() => randomSalt()); // in-process only; never written
  const commitments = encoded.map((e, i) => encodedRecordCommitment(e, salts[i]));
  const selected = Math.floor(protocol.records / 2);
  const timed = async <T>(fn: () => Promise<T>) => { const t0 = performance.now(); const value = await fn(); return { value, ms: performance.now() - t0 }; };

  for (const height of protocol.heights) {
    const { Witness, program } = membershipProgramForHeight(height);
    const analysis = (await program.analyzeMethods()).proveRecord;
    const tree = new MerkleTree(height);
    commitments.forEach((c, i) => tree.setLeaf(BigInt(i), c));
    const root = tree.getRoot();
    const witness = new Witness(tree.getWitness(BigInt(selected)));
    metadata.circuits.push({ treeHeight: height, capacity: (2n ** BigInt(height - 1)).toString(), witnessPathLength: witness.path.length, rows: analysis.rows, digest: analysis.digest });
    save();
    const query = new MembershipQuery({ root, requestedRecordIdHash: hashIdentifier(records[selected].recordId) });

    let ok = true;
    try {
      const c = await timed(() => program.compile({ cache, proofsEnabled: true }));
      log({ runId, operation: 'height-compile', treeHeight: height, phase: 'measured', attempt: 1, status: 'success', elapsedMs: c.ms });
    } catch (e) {
      ok = false; log({ runId, operation: 'height-compile', treeHeight: height, phase: 'measured', attempt: 1, status: 'failure', elapsedMs: null, error: (e as Error)?.name ?? 'Error' });
    }
    const slots = [
      ...Array.from({ length: protocol.proofWarmups }, (_, i) => ({ phase: 'warmup' as const, attempt: i + 1 })),
      ...Array.from({ length: protocol.proofMeasured }, (_, i) => ({ phase: 'measured' as const, attempt: i + 1 })),
    ];
    for (const { phase, attempt } of slots) {
      if (!ok) {
        if (phase === 'measured') log({ runId, operation: 'height-proof', treeHeight: height, phase, attempt, status: 'skipped', elapsedMs: null });
        continue;
      }
      try {
        const p = await timed(() => program.proveRecord(query, encoded[selected], salts[selected], witness));
        log({ runId, operation: 'height-proof', treeHeight: height, phase, attempt, status: 'success', elapsedMs: p.ms });
        const verifications = phase === 'warmup' ? 1 : protocol.verifications;
        for (let v = 1; v <= verifications; v++) {
          const r = await timed(async () => {
            assert.equal(await program.verify(p.value.proof), true);
            assert.equal(p.value.proof.publicInput.root.toString(), root.toString());
            assert.equal(p.value.proof.publicInput.requestedRecordIdHash.toString(), query.requestedRecordIdHash.toString());
          });
          log({ runId, operation: 'height-verify', treeHeight: height, phase, attempt: (attempt - 1) * verifications + v, status: 'success', elapsedMs: r.ms });
        }
      } catch (e) {
        ok = false; log({ runId, operation: 'height-proof', treeHeight: height, phase, attempt, status: 'failure', elapsedMs: null, error: (e as Error)?.name ?? 'Error' });
      }
    }
  }

  const groups = new Map<string, number[]>();
  for (const r of rows) if (r.phase === 'measured' && r.status === 'success') {
    const k = `${r.operation}|${r.treeHeight}`; groups.set(k, [...(groups.get(k) ?? []), r.elapsedMs!]);
  }
  metadata.summaries = [...groups].map(([k, xs]) => {
    const [operation, h] = k.split('|');
    return { operation, treeHeight: Number(h), n: xs.length, minMs: Math.min(...xs), medianMs: quantile(xs, 0.5), maxMs: Math.max(...xs), q1Ms: quantile(xs, 0.25), q3Ms: quantile(xs, 0.75) };
  });
  writeFileSync(join(directory, 'summaries.json'), JSON.stringify(metadata.summaries, null, 2) + '\n');
  metadata.outcome = rows.every((r) => r.status === 'success') ? 'completed' : 'completed-with-failures-or-skips';
  metadata.completedAt = new Date().toISOString();
  metadata.memory.availableAtEndBytes = freemem();
  metadata.cache.filesAfter = existsSync(PROOF_CACHE_PATH) ? filesIn(PROOF_CACHE_PATH).length : 0;
  save();
  console.log(JSON.stringify({ runId, outcome: metadata.outcome, circuits: metadata.circuits.map(({ treeHeight, rows }) => ({ treeHeight, rows })) }));
}
