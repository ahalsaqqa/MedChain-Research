import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { Field, setNumberOfWorkers } from 'o1js';
import { ContentStore } from '../src/storage.js';
import { Keyring } from '../src/keyring.js';
import { syntheticRecords } from '../src/fixtures.js';
import { buildSnapshot } from '../src/registry.js';
import { MembershipProgram, MembershipProof, MembershipQuery } from '../src/membership.js';
import { hashIdentifier } from '../src/records.js';
import { MedChainSession, RegistryChain } from '../src/workflow.js';

// Real storage/crypto; the chain adapter injects publication faults without proving.
describe('session integration (functional mode; no cryptographic proof verification)', () => {
  let directory: string;
  let root: Field;
  let events: string[];
  let rejectPublication: boolean;
  let rejectStorage: boolean;
  let store: ContentStore;
  let keyring: Keyring;
  let chain: RegistryChain;
  let session: MedChainSession;
  const records = syntheticRecords(12, 20261014);
  beforeAll(() => setNumberOfWorkers(1));
  beforeEach(async () => {
    const base = resolve('work/workflow-tests');
    await mkdir(base, { recursive: true });
    directory = await mkdtemp(join(base, 'run-'));
    root = buildSnapshot([]).root;
    events = [];
    rejectPublication = false;
    rejectStorage = false;
    store = new (class extends ContentStore {
      async put(bytes: Buffer) {
        events.push('store-start');
        if (rejectStorage) throw new Error('injected storage failure');
        const digest = await super.put(bytes);
        events.push('stored-and-checked');
        return digest;
      }
    })(directory);
    chain = {
      async currentRoot() { return Field(root.toBigInt()); },
      async publish(nextRoot) {
        events.push('publish');
        if (rejectPublication) throw new Error('injected publication failure');
        root = Field(nextRoot.toBigInt());
      },
    };
    keyring = new Keyring();
    session = new MedChainSession(store, keyring, chain);
  });
  afterEach(async () => {
    if (!directory.startsWith(resolve('work/workflow-tests') + sep))
      throw new Error('cleanup path escaped owned test directory');
    await rm(directory, { recursive: true, force: true });
  });

  test('persists and checks ciphertext before publishing, then decrypts the caller record', async () => {
    const result = await session.append(records[0]);
    expect(events).toEqual(['store-start', 'stored-and-checked', 'publish']);
    expect(result.root).toBe((await chain.currentRoot()).toString());
    expect(result.keyVersion).toBe(1);
    expect(await session.retrieve(records[0].recordId, result.digest)).toEqual(records[0]);
    expect(keyring.status()).toEqual({ activeVersion: 1, successfulWrites: 1 });
  });

  test('publication failure leaves an orphan, unchanged registry and no registered entry; queue recovers', async () => {
    const rootBefore = await chain.currentRoot();
    rejectPublication = true;
    await expect(session.append(records[0])).rejects.toThrow(/publication/);
    expect(await chain.currentRoot()).toEqual(rootBefore);
    await expect(session.prove(records[0].recordId)).rejects.toThrow(/not registered/);
    expect(await readdir(directory)).toHaveLength(1);
    expect(keyring.status()).toEqual({ activeVersion: 1, successfulWrites: 1 });
    rejectPublication = false;
    const retry = await session.append(records[0]);
    expect(await session.retrieve(records[0].recordId, retry.digest)).toEqual(records[0]);
    expect(keyring.status().successfulWrites).toBe(2);
  });

  test('failed storage never publishes or advances key policy, and permits retry', async () => {
    rejectStorage = true;
    await expect(session.append(records[0])).rejects.toThrow(/storage/);
    expect(events).toEqual(['store-start']);
    expect(keyring.status()).toEqual({ activeVersion: 1, successfulWrites: 0 });
    rejectStorage = false;
    const result = await session.append(records[0]);
    expect(await session.retrieve(records[0].recordId, result.digest)).toEqual(records[0]);
  });

  test('duplicate IDs reject within the queue before storage', async () => {
    const pending = [session.append(records[0]), session.append(records[0])];
    const settled = await Promise.allSettled(pending);
    expect(settled[0].status).toBe('fulfilled');
    expect(settled[1]).toMatchObject({ status: 'rejected', reason: new Error('duplicate recordId') });
    expect(events).toEqual(['store-start', 'stored-and-checked', 'publish']);
  });

  test('concurrent appends preserve all entries and own a validated copy at call time', async () => {
    const first = { ...records[0] };
    const pending = [session.append(first), session.append(records[1]), session.append(records[2])];
    first.quantity = 99999;
    const results = await Promise.all(pending);
    for (let i = 0; i < results.length; i++)
      expect(await session.retrieve(records[i].recordId, results[i].digest)).toEqual(records[i]);
    expect(new Set(results.map((result) => result.root)).size).toBe(3);
    expect(await chain.currentRoot()).toEqual(Field(results[2].root));
  });

  test('validates schema before storage and does not poison the queue', async () => {
    await expect(session.append({ ...records[0], quantity: 0 })).rejects.toThrow(/quantity/);
    expect(events).toEqual([]);
    await expect(session.append(records[0])).resolves.toHaveProperty('digest');
  });

  test('rejects stale snapshot for retrieve, prove and append before storage', async () => {
    const result = await session.append(records[0]);
    root = root.add(1);
    await expect(session.retrieve(records[0].recordId, result.digest)).rejects.toThrow(/stale/);
    await expect(session.prove(records[0].recordId)).rejects.toThrow(/stale/);
    events.length = 0;
    await expect(session.append(records[1])).rejects.toThrow(/stale/);
    expect(events).toEqual([]);
  });

  test('a legitimate envelope for B never satisfies caller A in the same current root', async () => {
    await session.append(records[0]);
    const b = await session.append(records[1]);
    await expect(session.retrieve(records[0].recordId, b.digest)).rejects.toThrow(/ID/);
    await expect(session.retrieve('unknown', b.digest)).rejects.toThrow(/not registered/);
  });

  test('missing ciphertext is a storage failure for a registered entry', async () => {
    await session.append(records[0]);
    await expect(session.retrieve(records[0].recordId, '0'.repeat(64))).rejects.toThrow(/missing content/);
  });

  test('eleventh failed write keeps version 1/count 10; retry commits version 2/count 1', async () => {
    const first = await session.append(records[0]);
    for (const record of records.slice(1, 10)) await session.append(record);
    rejectStorage = true;
    await expect(session.append(records[10])).rejects.toThrow(/storage/);
    expect(keyring.status()).toEqual({ activeVersion: 1, successfulWrites: 10 });
    rejectStorage = false;
    const retry = await session.append(records[10]);
    expect(retry.keyVersion).toBe(2);
    expect(keyring.status()).toEqual({ activeVersion: 2, successfulWrites: 1 });
    expect(await session.retrieve(records[0].recordId, first.digest)).toEqual(records[0]);
    expect(await session.retrieve(records[10].recordId, retry.digest)).toEqual(records[10]);
  });

  test('mock verification fails closed even for matching ID and current root', async () => {
    const result = await session.append(records[0]);
    const proof = await MembershipProof.dummy(new MembershipQuery({
      root: Field(result.root), requestedRecordIdHash: hashIdentifier(records[0].recordId),
    }), undefined, 0);
    MembershipProgram.setProofsEnabled(false);
    try {
      expect(await session.verify(proof, records[0].recordId)).toBe(false);
    } finally { MembershipProgram.setProofsEnabled(true); }
  });
});
