import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { cpus, freemem, platform, release, totalmem } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AccountUpdate, Cache, Field, MerkleTree, Mina, PrivateKey, setNumberOfWorkers } from 'o1js';
import { RegistryContract } from '../RegistryContract.js';
import { encryptRecord, openPayload, sealPayload, serializeEnvelope } from '../encryption.js';
import { SYNTHETIC_GENERATOR_VERSION, syntheticRecords } from '../fixtures.js';
import { MembershipProgram, MembershipProof, MembershipQuery } from '../membership.js';
import { encodeRecord, encodedRecordCommitment, hashIdentifier, randomSalt, validateRecord } from '../records.js';
import { buildSnapshot, RECORD_CAPACITY, RECORD_TREE_HEIGHT } from '../registry.js';
import { ContentStore } from '../storage.js';
import { Observation, ObservationWriter, Operation, Phase, PublicParameters, sanitizeError } from './observations.js';
import { measureOperation, Result, runMembershipTrials, runProofWorkIfSafe } from './scheduler.js';

export function protocolFor(smoke: boolean) {
  return smoke ? {
    protocol: 'smoke', reportable: false, sizes: [3], hostWarmups: 1, hostMeasured: 1,
    cryptoWarmups: 1, cryptoMeasured: 2, proofWarmups: 0, proofMeasured: 1, verifications: 2,
  } : {
    protocol: 'reportable-v1', reportable: true, sizes: [100, 500, 1000], hostWarmups: 1, hostMeasured: 5,
    cryptoWarmups: 5, cryptoMeasured: 30, proofWarmups: 1, proofMeasured: 5, verifications: 10,
  };
}
export function createRunDirectory(parent: string): { runId: string; directory: string } {
  mkdirSync(parent, { recursive: true });
  const runId = randomUUID();
  const directory = join(parent, runId);
  mkdirSync(directory); // Exclusive UUID child: never reuse/truncate an earlier run.
  return { runId, directory };
}
export function createScratchDirectory(runDirectory: string): string {
  const directory = join(runDirectory, 'scratch');
  mkdirSync(directory, { recursive: true });
  return directory;
}

const sha256 = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const cachePath = join(root, 'work', 'proof-cache');
function filesIn(directory: string): string[] {
  if (!existsSync(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) =>
    entry.isSymbolicLink() ? [] : entry.isDirectory() ? filesIn(join(directory, entry.name)) :
      entry.isFile() ? [join(directory, entry.name)] : []);
}
function provenance() {
  // Hash source/configuration, never run data, caches, or secret/ciphertext directories.
  const paths = ['src', 'tests'].flatMap((path) => filesIn(join(root, path)))
    .concat(['package.json', 'package-lock.json', 'tsconfig.json', 'jest.config.js', 'jest-resolver.cjs'].map((path) => join(root, path)))
    .filter(existsSync).sort();
  const manifest = paths.map((path) => ({ path: relative(root, path).replaceAll('\\', '/'), sha256: sha256(readFileSync(path)) }));
  const contentManifestHash = sha256(JSON.stringify(manifest));
  try {
    const git = (args: string[]) => execFileSync(process.env.MEDCHAIN_GIT ?? 'git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    assert.equal(resolve(git(['rev-parse', '--show-toplevel'])), root);
    const tracked = git(['status', '--porcelain', '--untracked-files=no']);
    const untracked = git(['ls-files', '--others', '--exclude-standard']).split('\n').filter(Boolean);
    return { codeSHA: git(['rev-parse', 'HEAD']), gitAvailable: true, trackedDirty: tracked.length > 0,
      trackedChangedFiles: tracked ? tracked.split('\n').length : 0, untrackedFiles: untracked.length,
      untrackedGraphifyFiles: untracked.filter((path) => path.startsWith('graphify-out/')).length,
      contentManifestHash, manifest };
  } catch {
    return { codeSHA: 'unavailable', gitAvailable: false, trackedDirty: null, trackedChangedFiles: null,
      untrackedFiles: null, untrackedGraphifyFiles: null, contentManifestHash, manifest };
  }
}
const CLOCK_BOUNDARIES = {
  clock: 'performance.now() monotonic milliseconds; observation/event I/O outside operation clock',
  warmups: 'Logged separately (not included in measured summaries); no performance claim from warmups',
  validation: 'validateRecord over all N records; semantic host validation only',
  encoding: 'encodeRecord over N validated records; includes its own host validation and identifier hashing',
  commitments: 'encodedRecordCommitment over pre-encoded records and independently random 128-bit salts',
  tree: 'new MerkleTree(11), N setLeaf calls, getRoot over precomputed commitments; root checked against RegistrySnapshot outside clock',
  aes: 'Whole-dataset loop of shared sealPayload/openPayload only, with loop/buffer allocation overhead. Canonical payload/AAD, random keys, fresh nonce arrays and RNG, encoding, commitments, storage and rotation excluded. Decryption equality checked after clock',
  storageWrite: 'Sequential ContentStore.put over N prepared serialized envelopes, includes exact-byte hash, safe file I/O and ContentStore integrity read; excludes AES/envelope preparation, directory allocation and later file/byte audit. Fresh attempt directory every time',
  storageRead: 'Sequential ContentStore.get over same N digests, includes digest integrity checks. Warm/cache-affected, immediately follows write; no OS cache flush',
  compile: 'SDK compile calls separately, reused filesystem cache; no cold-start claim',
  updateProof: 'transaction.prove only, prepared authorized local update, one actual proof per N (feasibility n=1); deployment/transaction assembly/finalization excluded and separately logged',
  membershipProof: 'MembershipProgram.proveRecord only with prepared query, encoded record, salt and witness at floor(N/2); exactly one record and fixed path length; compiled program excluded',
  membershipVerify: 'MembershipProgram.verify plus caller expected-root/ID-hash comparison; proof JSON serialization and file I/O excluded',
};

/** Always actual proofs. Smoke only reduces workloads and is explicitly nonreportable. */
export async function runExperiments(options: { outputDir: string; seed: number; proofMode: 'real'; smoke?: boolean }): Promise<void> {
  assert.equal(options.proofMode, 'real', 'benchmark accepts only actual proof mode');
  assert.notEqual(process.env.MEDCHAIN_REAL_PROOFS, 'false', 'actual proofs must be enabled');
  assert(Number.isSafeInteger(options.seed), 'seed must be a safe integer');
  const protocol = protocolFor(options.smoke === true);
  const { runId, directory } = createRunDirectory(resolve(options.outputDir));
  const writer = new ObservationWriter(directory);
  const source = provenance();
  const sdk = JSON.parse(readFileSync(join(root, 'node_modules', 'o1js', 'package.json'), 'utf8')).version;
  assert.equal(sdk, '2.2.0', 'benchmark requires pinned o1js');
  const metadata = {
    runId, createdAt: new Date().toISOString(), completedAt: null as string | null,
    outcome: 'running', ...protocol, seed: options.seed, generatorVersion: SYNTHETIC_GENERATOR_VERSION,
    source, dependencyLockHash: sha256(readFileSync(join(root, 'package-lock.json'))),
    node: process.version, o1js: sdk, os: { platform: platform(), release: release(), architecture: process.arch },
    cpu: { model: cpus()[0]?.model ?? 'unavailable', logicalCpus: cpus().length },
    memory: { totalBytes: totalmem(), availableAtStartBytes: freemem(), availableAtEndBytes: null as number | null },
    proofMode: 'real', proofsEnabled: true, workers: 1, provingProcesses: 1,
    treeHeight: RECORD_TREE_HEIGHT, verifiedCapacity: RECORD_CAPACITY,
    cache: { relativePath: 'work/proof-cache', filesBefore: filesIn(cachePath).length, filesAfter: null as number | null,
      policy: 'reuse SDK filesystem cache, no forceRecompile; warm/cache-affected compilation; no cold claim' },
    clockBoundaries: CLOCK_BOUNDARIES,
    abortPolicy: 'On first proof/verification/setup failure, preserve sanitized diagnostic and skip remaining heavy proof/verification slots without retries; continue lightweight host/AES/storage datasets when safe. A hard process interruption leaves start events and prior JSONL rows.',
    secrecy: 'Keys/salts/plaintext/witnesses retained only in process; scratch ciphertext removed after saved observations. Only public proofs/verification keys exported. No raw exception messages or stacks.',
    scope: 'Synthetic local feasibility experiment; fixed path length, no production throughput/energy/fraud or network comparison claim',
    summaryRecomputedFromJSONL: false,
  };
  const saveMetadata = () => writeFileSync(join(directory, 'metadata.json'), JSON.stringify(metadata, null, 2) + '\n');
  saveMetadata();
  console.log(JSON.stringify({ runId, protocol: protocol.protocol, event: 'run-start', codeSHA: source.codeSHA }));
  const observationContext = { writer, runId, treeHeight: RECORD_TREE_HEIGHT, reportable: protocol.reportable };
  async function measure<T>(operation: Operation, N: number, phase: Phase, attempt: number,
    fn: () => T | Promise<T>, count: number, parameters: PublicParameters = {},
    audit?: (value: T) => Partial<Pick<Observation, 'files' | 'bytes'>>): Promise<Result<T>> {
    return measureOperation(observationContext, operation, N, phase, attempt, fn, count, parameters, audit);
  }
  function skip(operation: Operation, N: number, phase: Phase, attempt: number,
    abortReason: 'proof-failure' | 'setup-failure', parameters: PublicParameters = {}): Observation {
    const row: Observation = { runId, operation, N, phase, attempt, status: 'skipped', elapsedMs: null, recordsProcessed: 0,
      publicParameters: { treeHeight: RECORD_TREE_HEIGHT, reportable: protocol.reportable, abortReason, ...parameters } };
    writer.append(row); return row;
  }
  function phaseEvent(phase: string, N?: number) {
    console.log(JSON.stringify({ runId, event: 'phase', phase, ...(N === undefined ? {} : { N }) }));
  }
  const attempts = (warmups: number, measured: number) => [
    ...Array.from({ length: warmups }, (_, i) => ({ phase: 'warmup' as const, attempt: i + 1 })),
    ...Array.from({ length: measured }, (_, i) => ({ phase: 'measured' as const, attempt: i + 1 })),
  ];
  const proofSafety = { unsafe: false };
  let contract: RegistryContract | undefined;
  let administrator: Awaited<ReturnType<typeof Mina.LocalBlockchain>>['testAccounts'][number] | undefined;
  try {
    setNumberOfWorkers(1);
    phaseEvent('compile-membership');
    const membershipCompilation = await measure('compile-membership', 0, 'measured', 1,
      () => MembershipProgram.compile({ cache: Cache.FileSystem(cachePath), proofsEnabled: true }), 0,
      { boundary: 'sdk-cache-compilation', cacheAffected: true });
    if (membershipCompilation.ok) {
      const vk = membershipCompilation.value.verificationKey;
      writeFileSync(join(directory, 'membership-verification-key.json'), JSON.stringify({ data: vk.data, hash: vk.hash.toString(), dataSHA256: sha256(vk.data) }, null, 2) + '\n');
    } else proofSafety.unsafe = true;
    phaseEvent('compile-registry');
    const contractCompilation = proofSafety.unsafe ? undefined : await measure('compile-registry', 0, 'measured', 1,
      () => RegistryContract.compile({ cache: Cache.FileSystem(cachePath) }), 0,
      { boundary: 'sdk-cache-compilation', cacheAffected: true });
    if (contractCompilation?.ok) {
      const vk = contractCompilation.value.verificationKey;
      writeFileSync(join(directory, 'registry-verification-key.json'), JSON.stringify({ data: vk.data, hash: vk.hash.toString(), dataSHA256: sha256(vk.data) }, null, 2) + '\n');
    } else {
      if (proofSafety.unsafe) skip('compile-registry', 0, 'measured', 1, 'setup-failure');
      proofSafety.unsafe = true;
    }
    if (!proofSafety.unsafe) {
      assert.equal(MembershipProgram.proofsEnabled, true);
      const local = await Mina.LocalBlockchain({ proofsEnabled: true });
      Mina.setActiveInstance(local); assert.equal(Mina.getProofsEnabled(), true);
      [administrator] = local.testAccounts;
      const contractKey = PrivateKey.random();
      contract = new RegistryContract(contractKey.toPublicKey());
      const deployed = await measure('registry-deployment', 0, 'setup', 1, async () => {
        const tx = await Mina.transaction(administrator!, async () => {
          AccountUpdate.fundNewAccount(administrator!); await contract!.deploy();
          await contract!.initialize(buildSnapshot([]).root, administrator!);
        });
        await tx.prove();
        assert.equal((await (await tx.sign([administrator!.key, contractKey]).send()).wait()).status, 'included');
      }, 0, { boundary: 'signed-local-deployment' });
      if (!deployed.ok) proofSafety.unsafe = true;
    } else skip('registry-deployment', 0, 'setup', 1, 'setup-failure');

    for (const N of protocol.sizes) {
      phaseEvent('host-workloads', N);
      const records = syntheticRecords(N, options.seed);
      const salts = records.map(() => randomSalt());
      const encoded = records.map(encodeRecord);
      const commitments = encoded.map((record, i) => encodedRecordCommitment(record, salts[i]));
      const snapshot = buildSnapshot(records.map((record, i) => ({ record, salt: salts[i] })));
      const selectedIndex = Math.floor(N / 2);
      for (const { phase, attempt } of attempts(protocol.hostWarmups, protocol.hostMeasured)) {
        await measure('validation', N, phase, attempt, () => records.map(validateRecord), N, { boundary: 'host-validation' });
        await measure('encoding', N, phase, attempt, () => records.map(encodeRecord), N, { boundary: 'encoding-includes-validation' });
        await measure('commitments', N, phase, attempt, () => encoded.map((record, i) => encodedRecordCommitment(record, salts[i])), N, { boundary: 'preencoded-commitments' });
        const tree = await measure('tree', N, phase, attempt, () => {
          const tree = new MerkleTree(RECORD_TREE_HEIGHT);
          assert.equal(tree.leafCount, BigInt(RECORD_CAPACITY));
          commitments.forEach((commitment, i) => tree.setLeaf(BigInt(i), commitment));
          return tree.getRoot();
        }, N, { boundary: 'precomputed-tree' }, (treeRoot) => {
          assert.equal(treeRoot.toString(), snapshot.root.toString(), 'tree root disagrees with trusted snapshot'); return {};
        });
      }

      phaseEvent('aes-storage-workloads', N);
      const key = randomBytes(32);
      const envelopes = records.map((record, i) => encryptRecord(record, salts[i], key, 1));
      // Shared production encryption creates canonical plaintext; preparation is outside every clock.
      const prepared = envelopes.map((envelope) => {
        const { version, algorithm, keyVersion, requestedRecordIdHash, recordCommitment } = envelope;
        const aad = Buffer.from(JSON.stringify({ version, algorithm, keyVersion, requestedRecordIdHash, recordCommitment }));
        const plaintext = openPayload(Buffer.from(envelope.ciphertext, 'base64'), Buffer.from(envelope.tag, 'base64'), key, Buffer.from(envelope.nonce, 'base64'), aad);
        return { aad, plaintext };
      });
      const serialized = envelopes.map(serializeEnvelope);
      const expectedBytes = serialized.reduce((sum, bytes) => sum + bytes.length, 0);
      const scratchRoot = createScratchDirectory(directory);
      for (const { phase, attempt } of attempts(protocol.cryptoWarmups, protocol.cryptoMeasured)) {
        // Independent fresh random nonce per record/attempt, never seeded and never reused with this key.
        const nonces = records.map(() => randomBytes(12));
        const encrypted = await measure('aes-encrypt', N, phase, attempt,
          () => prepared.map(({ plaintext, aad }, i) => sealPayload(plaintext, key, nonces[i], aad)), N, { boundary: 'aes-only-prepared-inputs' });
        if (encrypted.ok) {
          const decrypted = await measure('aes-decrypt', N, phase, attempt,
            () => encrypted.value.map(({ ciphertext, tag }, i) => openPayload(ciphertext, tag, key, nonces[i], prepared[i].aad)), N, { boundary: 'aes-only-prepared-inputs' });
          if (decrypted.ok) decrypted.value.forEach((bytes, i) => { assert(bytes.equals(prepared[i].plaintext)); bytes.fill(0); });
        } else skip('aes-decrypt', N, phase, attempt, 'setup-failure');
        const attemptDirectory = join(scratchRoot, `attempt-${randomUUID()}`); mkdirSync(attemptDirectory);
        const store = new ContentStore(attemptDirectory);
        const written = await measure('storage-write', N, phase, attempt, async () => {
          const digests: string[] = []; for (const bytes of serialized) digests.push(await store.put(bytes)); return digests;
        }, N, { boundary: 'prepared-envelope-storage' }, () => {
          const files = readdirSync(attemptDirectory);
          const bytes = files.reduce((sum, file) => sum + statSync(join(attemptDirectory, file)).size, 0);
          assert.equal(files.length, N); assert.equal(bytes, expectedBytes);
          return { files: files.length, bytes };
        });
        if (written.ok) {
          const retrieved = await measure('storage-read', N, phase, attempt, async () => {
            const buffers: Buffer[] = []; for (const digest of written.value) buffers.push(await store.get(digest)); return buffers;
          }, N, { boundary: 'warm-content-read', cacheAffected: true }, (buffers) => ({ files: buffers.length, bytes: buffers.reduce((sum, bytes) => sum + bytes.length, 0) }));
          if (retrieved.ok) retrieved.value.forEach((value, i) => assert(value.equals(serialized[i])));
        } else skip('storage-read', N, phase, attempt, 'setup-failure');
        // Only this owned, regular direct child may be recursively removed, after rows are persisted.
        assert.equal(realpathSync(scratchRoot), resolve(scratchRoot));
        assert.equal(dirname(resolve(attemptDirectory)), resolve(scratchRoot));
        assert(!isAbsolute(relative(scratchRoot, attemptDirectory)) && !relative(scratchRoot, attemptDirectory).startsWith('..'));
        assert(lstatSync(attemptDirectory).isDirectory() && !lstatSync(attemptDirectory).isSymbolicLink());
        assert.equal(realpathSync(attemptDirectory), resolve(attemptDirectory));
        rmSync(attemptDirectory, { recursive: true });
      }
      key.fill(0); prepared.forEach(({ plaintext }) => plaintext.fill(0));
      phaseEvent('registry-update', N);
      await runProofWorkIfSafe(proofSafety, async () => {
        const preparedUpdate = await measure('registry-update-prepare', N, 'setup', 1,
          () => Mina.transaction(administrator!, async () => { await contract!.updateRoot(snapshot.root); }), 0, { boundary: 'local-update-prepare' });
        if (preparedUpdate.ok) {
          const proved = await measure('registry-update-proof', N, 'measured', 1, () => preparedUpdate.value.prove(), 0,
            { boundary: 'transaction-prove-only' }, (transaction) => {
              assert(transaction.proofs.some((proof) => proof !== undefined), 'update must carry actual proof'); return {};
            });
          if (proved.ok) {
            const finalized = await measure('registry-update-finalize', N, 'setup', 1, async () => {
              assert.equal((await (await proved.value.sign([administrator!.key]).send()).wait()).status, 'included');
              assert.equal(Mina.getAccount(contract!.address).zkapp!.appState[0].toString(), snapshot.root.toString());
            }, 0, { boundary: 'local-update-finalize' });
            if (!finalized.ok) proofSafety.unsafe = true;
          } else proofSafety.unsafe = true;
        } else { proofSafety.unsafe = true; skip('registry-update-proof', N, 'measured', 1, 'setup-failure'); }
      }, () => { skip('registry-update-proof', N, 'measured', 1, 'proof-failure'); });

      phaseEvent('membership-proofs', N);
      const id = records[selectedIndex].recordId;
      const expectedHash = hashIdentifier(id);
      const query = new MembershipQuery({ root: snapshot.root, requestedRecordIdHash: expectedHash });
      const witness = snapshot.witness(id);
      let savedProof = false;
      await runMembershipTrials({
        safety: proofSafety, warmups: protocol.proofWarmups, measured: protocol.proofMeasured, verifications: protocol.verifications,
        prove: (phase, attempt) => measure('membership-proof', N, phase, attempt, async () => {
          const { proof } = await MembershipProgram.proveRecord(query, encoded[selectedIndex], salts[selectedIndex], witness); return proof;
        }, 1, { selectedIndex, boundary: 'prepared-membership-prove' }),
        verify: (proof: MembershipProof, phase, attempt, trial) =>
          measure('membership-verify', N, phase, phase === 'warmup' ? trial : (attempt - 1) * protocol.verifications + trial,
            async () => {
              assert.equal(await MembershipProgram.verify(proof), true);
              assert.equal(proof.publicInput.root.toString(), snapshot.root.toString());
              assert.equal(proof.publicInput.requestedRecordIdHash.toString(), expectedHash.toString());
            }, 1, { selectedIndex, proofAttempt: attempt, boundary: 'cryptographic-and-anchor-verify' }),
        skipProof: (phase, attempt) => skip('membership-proof', N, phase, attempt, 'proof-failure', { selectedIndex, boundary: 'prepared-membership-prove' }),
        skipVerification: (phase, attempt, trial) => {
          skip('membership-verify', N, phase, phase === 'warmup' ? trial : (attempt - 1) * protocol.verifications + trial,
            'proof-failure', { selectedIndex, proofAttempt: attempt, boundary: 'cryptographic-and-anchor-verify' });
        },
        append: (row) => writer.append(row),
        onMeasuredProof: (proof) => {
          if (!savedProof) {
            writeFileSync(join(directory, `membership-proof-N${N}.json`), JSON.stringify(proof.toJSON(), null, 2) + '\n'); savedProof = true;
          }
        },
      });
      phaseEvent('dataset-complete', N);
    }
    metadata.outcome = writer.rows.some((row) => row.status !== 'success') ? 'completed-with-failures-or-skips' : 'completed';
  } catch (error) {
    metadata.outcome = 'aborted';
    writer.append({ runId, operation: 'run', N: 0, phase: 'setup', attempt: 1, status: 'failure', elapsedMs: 0, recordsProcessed: 0,
      error: sanitizeError(error, 'run'), publicParameters: { reportable: protocol.reportable } });
  } finally {
    writer.finalize();
    metadata.summaryRecomputedFromJSONL = true;
    metadata.completedAt = new Date().toISOString(); metadata.memory.availableAtEndBytes = freemem();
    metadata.cache.filesAfter = filesIn(cachePath).length;
    saveMetadata();
    phaseEvent(metadata.outcome);
  }
  if (metadata.outcome !== 'completed') throw new Error('benchmark retained failures or skipped work; inspect sanitized run artifacts');
}
