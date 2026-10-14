import { existsSync, readdirSync } from 'node:fs';
import { freemem, totalmem } from 'node:os';
import {
  AccountUpdate,
  Cache,
  Field,
  Mina,
  PrivateKey,
  setNumberOfWorkers,
} from 'o1js';
import { RegistryContract } from '../src/RegistryContract.js';
import { syntheticRecords } from '../src/fixtures.js';
import {
  MembershipProgram,
  MembershipProof,
  MembershipQuery,
  proveMembership,
  verifyCurrentMembership,
} from '../src/membership.js';
import { hashIdentifier, randomSalt } from '../src/records.js';
import { buildSnapshot } from '../src/registry.js';
import { createPilotLog } from './helpers/pilot-log.js';
import { createPilotReporter } from './helpers/pilot-phase.js';

// Kept out of the functional command. Every proof and transaction here uses actual proving.
test('actual-proof pilot: authorized update, cryptography and independent root/query anchors', async () => {
  const logDir = 'work/pilot-public';
  const logPath = createPilotLog(
    logDir,
    process.env.MEDCHAIN_PILOT_RUN ?? 'latest'
  );
  const { event, phase } = createPilotReporter(logPath);
  event({
    phase: 'metadata',
    logPath,
    proofMode: 'actual',
    proofsEnabled: true,
    workers: 1,
    node: process.version,
    o1js: '2.2.0',
    pid: process.pid,
    totalMemoryBytes: totalmem(),
    freeMemoryBytes: freemem(),
  });
  if (
    process.env.MEDCHAIN_REAL_PROOFS === 'false' ||
    !MembershipProgram.proofsEnabled
  )
    throw new Error('Actual proving must be enabled for the real-proof suite');
  setNumberOfWorkers(1);
  const cachePath = 'work/proof-cache';
  const cacheFilesBefore = existsSync(cachePath)
    ? readdirSync(cachePath).length
    : 0;
  event({
    phase: 'cache',
    cachePath,
    cacheFilesBefore,
    cachePolicy: 'SDK filesystem cache; no forceRecompile',
  });
  const cache = Cache.FileSystem(cachePath);
  await phase('compile-membership', () =>
    MembershipProgram.compile({ cache, proofsEnabled: true })
  );
  await phase('compile-contract', () => RegistryContract.compile({ cache }));
  expect(MembershipProgram.proofsEnabled).toBe(true);
  const local = await Mina.LocalBlockchain({ proofsEnabled: true });
  Mina.setActiveInstance(local);
  expect(Mina.getProofsEnabled()).toBe(true);
  const [admin, attacker] = local.testAccounts;
  const key = PrivateKey.random();
  const contract = new RegistryContract(key.toPublicKey());
  const records = syntheticRecords(3, 20261014);
  const entries = records.map((record) => ({ record, salt: randomSalt() }));
  const old = buildSnapshot(entries.slice(0, 2));
  const snapshot = buildSnapshot(entries);
  const deployment = await phase('construct-deployment', () =>
    Mina.transaction(admin, async () => {
      AccountUpdate.fundNewAccount(admin);
      await contract.deploy();
      await contract.initialize(old.root, admin);
    })
  );
  await phase('prove-deployment', () => deployment.prove());
  await phase('send-deployment', async () => {
    const sent = await deployment.sign([admin.key, key]).send();
    expect((await sent.wait()).status).toBe('included');
  });
  expect(
    Mina.getAccount(contract.address)
      .zkapp!.appState[0].equals(old.root)
      .toBoolean()
  ).toBe(true);
  const update = await phase('construct-authorized-update', () =>
    Mina.transaction(admin, async () => {
      await contract.updateRoot(snapshot.root);
    })
  );
  const proved = await phase('prove-authorized-update', () => update.prove());
  expect(proved.proofs.some((proof) => proof !== undefined)).toBe(true);
  await phase('send-authorized-update', async () => {
    const sent = await proved.sign([admin.key]).send();
    expect((await sent.wait()).status).toBe('included');
  });
  const currentRoot = Mina.getAccount(contract.address).zkapp!.appState[0];
  expect(currentRoot.equals(snapshot.root).toBoolean()).toBe(true);
  await expect(
    Mina.transaction(attacker, async () => {
      await contract.updateRoot(Field(999));
    })
  ).rejects.toThrow(/administrator/);
  expect(
    Mina.getAccount(contract.address)
      .zkapp!.appState[0].equals(currentRoot)
      .toBoolean()
  ).toBe(true);
  const recordA = records[0];
  const recordB = records[1];
  const proofForB = await phase('prove-membership-current', () =>
    proveMembership(snapshot, recordB.recordId)
  );
  await phase('verify-cryptography-current', async () => {
    expect(await MembershipProgram.verify(proofForB)).toBe(true);
  });
  await phase('verify-independent-current-query', async () => {
    expect(
      await verifyCurrentMembership(proofForB, currentRoot, recordA.recordId)
    ).toBe(false);
    expect(
      await verifyCurrentMembership(proofForB, currentRoot, recordB.recordId)
    ).toBe(true);
  });
  await phase('reject-modified-public-inputs', async () => {
    for (const publicInput of [
      new MembershipQuery({
        root: currentRoot.add(1),
        requestedRecordIdHash: hashIdentifier(recordB.recordId),
      }),
      new MembershipQuery({
        root: currentRoot,
        requestedRecordIdHash: hashIdentifier(recordA.recordId),
      }),
    ]) {
      const modified = new MembershipProof({
        proof: proofForB.proof,
        publicInput,
        publicOutput: undefined,
        maxProofsVerified: proofForB.maxProofsVerified,
      });
      expect(await MembershipProgram.verify(modified)).toBe(false);
      expect(
        await verifyCurrentMembership(
          modified,
          publicInput.root,
          publicInput.requestedRecordIdHash
            .equals(hashIdentifier(recordA.recordId))
            .toBoolean()
            ? recordA.recordId
            : recordB.recordId
        )
      ).toBe(false);
    }
  });
  const staleProof = await phase('prove-membership-stale', () =>
    proveMembership(old, recordB.recordId)
  );
  await phase('reject-stale-root', async () => {
    expect(await MembershipProgram.verify(staleProof)).toBe(true);
    expect(
      await verifyCurrentMembership(staleProof, currentRoot, recordB.recordId)
    ).toBe(false);
  });
  const attackerSnapshot = buildSnapshot([
    { record: { ...recordB, quantity: 999 }, salt: randomSalt() },
  ]);
  const attackerProof = await phase('prove-membership-attacker-root', () =>
    proveMembership(attackerSnapshot, recordB.recordId)
  );
  await phase('reject-attacker-root', async () => {
    expect(await MembershipProgram.verify(attackerProof)).toBe(true);
    expect(
      await verifyCurrentMembership(
        attackerProof,
        currentRoot,
        recordB.recordId
      )
    ).toBe(false);
  });
  event({
    phase: 'pilot',
    status: 'complete',
    outcome: 'passed',
    cacheFilesAfter: readdirSync(cachePath).length,
  });
}, 3_600_000);
