import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { AccountUpdate, Cache, Mina, PrivateKey, setNumberOfWorkers } from 'o1js';
import { RegistryContract } from './RegistryContract.js';
import { syntheticRecords } from './fixtures.js';
import { Keyring } from './keyring.js';
import { MembershipProgram } from './membership.js';
import { buildSnapshot } from './registry.js';
import { ContentStore } from './storage.js';
import { MedChainSession, RegistryChain } from './workflow.js';

const runId = randomUUID();
const runDirectory = join('work', `demo-${runId}`);
const evidenceDirectory = join('docs', 'research', 'task-4');
mkdirSync(runDirectory, { recursive: true });
mkdirSync(evidenceDirectory, { recursive: true });
const evidencePath = join(evidenceDirectory, `demo-${runId}.json`);
const cachePath = 'work/proof-cache';
const evidence: {
  runId: string; node: string; o1js: string; proofMode: string;
  proofsEnabled: boolean; workers: number; storage: string; keyCustody: string;
  cache: object; phases: object[]; outcome: string; result?: object;
} = {
  runId, node: process.version, o1js: '2.2.0', proofMode: 'actual',
  proofsEnabled: true, workers: 1, storage: 'local SHA-256 content store (not IPFS)',
  keyCustody: 'fresh process-memory keys; unavailable after exit',
  cache: { path: cachePath, filesBefore: existsSync(cachePath) ? readdirSync(cachePath).length : 0,
    policy: 'reuse SDK filesystem cache without forceRecompile; compile timings may be warm' },
  phases: [], outcome: 'running',
};
writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx' });
function event(row: object) {
  const data = { at: new Date().toISOString(), ...row };
  evidence.phases.push(data);
  writeFileSync(evidencePath, JSON.stringify(evidence, null, 2) + '\n');
  console.log(JSON.stringify(data));
}
async function phase<T>(name: string, operation: () => Promise<T>): Promise<T> {
  event({ phase: name, status: 'start' });
  const started = performance.now();
  try {
    const result = await operation();
    event({ phase: name, status: 'complete', elapsedMs: performance.now() - started });
    return result;
  } catch (error) {
    // SDK diagnostics may contain private witnesses. Preserve them only in ignored work/.
    writeFileSync(join(runDirectory, 'private-error.txt'), error instanceof Error ? error.stack ?? error.message : String(error));
    event({ phase: name, status: 'failed', errorType: error instanceof Error ? error.name : 'UnknownError' });
    throw error;
  }
}

async function main() {
  assert.notEqual(process.env.MEDCHAIN_REAL_PROOFS, 'false', 'actual proofs must be enabled');
  setNumberOfWorkers(1);
  const cache = Cache.FileSystem(cachePath);
  await phase('compile-membership', () => MembershipProgram.compile({ cache, proofsEnabled: true }));
  await phase('compile-contract', () => RegistryContract.compile({ cache }));
  assert.equal(MembershipProgram.proofsEnabled, true);
  const local = await Mina.LocalBlockchain({ proofsEnabled: true });
  Mina.setActiveInstance(local);
  assert.equal(Mina.getProofsEnabled(), true);
  const [administrator] = local.testAccounts;
  const contractKey = PrivateKey.random();
  const contract = new RegistryContract(contractKey.toPublicKey());
  const emptyRoot = buildSnapshot([]).root;
  await phase('signed-deployment-not-a-ZK-update-measurement', async () => {
    const transaction = await Mina.transaction(administrator, async () => {
      AccountUpdate.fundNewAccount(administrator);
      await contract.deploy();
      await contract.initialize(emptyRoot, administrator);
    });
    await transaction.prove();
    const pending = await transaction.sign([administrator.key, contractKey]).send();
    assert.equal((await pending.wait()).status, 'included');
  });
  const chain: RegistryChain = {
    async currentRoot() {
      // Independent ledger state; never return the session's prepared root.
      return Mina.getAccount(contract.address).zkapp!.appState[0];
    },
    async publish(nextRoot) {
      const transaction = await Mina.transaction(administrator, async () => {
        await contract.updateRoot(nextRoot);
      });
      const proved = await phase('prove-authorized-registry-update', () => transaction.prove());
      assert(proved.proofs.some((proof) => proof !== undefined), 'registry update must carry an actual proof');
      await phase('finalize-authorized-registry-update', async () => {
        const pending = await proved.sign([administrator.key]).send();
        assert.equal((await pending.wait()).status, 'included');
        assert((await chain.currentRoot()).equals(nextRoot).toBoolean(), 'published root must be finalized');
      });
    },
  };
  assert((await chain.currentRoot()).equals(emptyRoot).toBoolean());
  const keyring = new Keyring();
  const session = new MedChainSession(new ContentStore(join(runDirectory, 'content')), keyring, chain);
  const [record] = syntheticRecords(1, 20261014);
  const stored = await phase('encrypted-write-and-root-publication', () => session.append(record));
  await phase('checked-read-and-authenticated-decryption', async () => {
    assert.deepEqual(await session.retrieve(record.recordId, stored.digest), record);
  });
  const proof = await phase('prove-membership', () => session.prove(record.recordId));
  await phase('verify-current-root-and-caller-ID', async () => {
    assert.equal(await session.verify(proof, record.recordId), true);
    assert.equal(await session.verify(proof, 'different-caller-ID'), false);
  });
  evidence.outcome = 'passed';
  evidence.result = {
    records: 1, encryptedRoundTrips: 1, authorizedRealProofUpdates: 1,
    actualMembershipProofAccepted: true, wrongCallerIDRejected: true,
    initialRoot: emptyRoot.toString(), currentRoot: (await chain.currentRoot()).toString(),
    keyVersion: stored.keyVersion, successfulEncryptedWrites: keyring.status().successfulWrites,
    cacheFilesAfter: readdirSync(cachePath).length,
  };
  event({ phase: 'demo', status: 'complete', outcome: evidence.outcome, evidencePath });
}
try { await main(); }
catch (error) {
  evidence.outcome = 'failed';
  writeFileSync(join(runDirectory, 'private-error.txt'), error instanceof Error ? error.stack ?? error.message : String(error));
  event({ phase: 'demo', status: 'failed', errorType: error instanceof Error ? error.name : 'UnknownError', evidencePath });
  process.exitCode = 1;
}
