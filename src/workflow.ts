import { Field } from 'o1js';
import { ContentStore } from './storage.js';
import { Keyring } from './keyring.js';
import { MedicineRecord, randomSalt, validateRecord } from './records.js';
import { MembershipProof, proveMembership, verifyCurrentMembership } from './membership.js';
import { buildSnapshot, RECORD_CAPACITY, RegistryEntry, RegistrySnapshot } from './registry.js';
import { decryptRecord, encryptRecord, serializeEnvelope, validateEnvelope } from './encryption.js';

export interface RegistryChain {
  currentRoot(): Promise<Field>;
  publish(nextRoot: Field): Promise<void>;
}

/** One trusted registrar session; keys and private snapshot inputs stay in process. */
export class MedChainSession {
  #snapshot = buildSnapshot([]);
  #entries: RegistryEntry[] = [];
  #writes: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly store: ContentStore,
    private readonly keyring: Keyring,
    private readonly chain: RegistryChain
  ) {}

  async #requireCurrent(snapshot: RegistrySnapshot): Promise<void> {
    if (!snapshot.root.equals(await this.chain.currentRoot()).toBoolean())
      throw new Error('stale registrar snapshot');
  }

  #registered(snapshot: RegistrySnapshot, id: string) {
    try { return snapshot.lookup(id); }
    catch { throw new Error('record ID not registered'); }
  }

  async append(record: MedicineRecord): Promise<{ digest: string; root: string; keyVersion: number }> {
    // Copy/validate now, before callers can mutate queued input.
    const owned = validateRecord(record);
    const operation = this.#writes.then(async () => {
      if (this.#entries.some((entry) => entry.record.recordId === owned.recordId))
        throw new Error('duplicate recordId');
      if (this.#entries.length >= RECORD_CAPACITY)
        throw new Error('registry capacity is 1024 records');
      await this.#requireCurrent(this.#snapshot);
      const salt = randomSalt();
      const entries = [...this.#entries, { record: owned, salt }];
      const preparedSnapshot = buildSnapshot(entries);
      const { version, key } = this.keyring.prepare();
      const bytes = serializeEnvelope(encryptRecord(owned, salt, key, version));
      const digest = await this.store.put(bytes);
      // put checks its read-back content digest; publication is a separate commit.
      this.keyring.commitWrite(version);
      await this.chain.publish(preparedSnapshot.root);
      this.#entries = entries;
      this.#snapshot = preparedSnapshot;
      return { digest, root: preparedSnapshot.root.toString(), keyVersion: version };
    });
    this.#writes = operation.catch(() => undefined);
    return operation;
  }
  async retrieve(id: string, digest: string): Promise<MedicineRecord> {
    const snapshot = this.#snapshot;
    const entry = this.#registered(snapshot, id);
    // The downloaded envelope is never the source of the expected commitment.
    const selectedRoot = snapshot.witness(id).calculateRoot(entry.commitment);
    if (!selectedRoot.equals(await this.chain.currentRoot()).toBoolean())
      throw new Error('stale registrar snapshot');
    const bytes = await this.store.get(digest);
    const envelope = validateEnvelope(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));
    return decryptRecord(envelope, this.keyring.get(envelope.keyVersion), {
      id, commitment: entry.commitment,
    }).record;
  }
  async prove(id: string): Promise<MembershipProof> {
    const snapshot = this.#snapshot;
    this.#registered(snapshot, id);
    await this.#requireCurrent(snapshot);
    return proveMembership(snapshot, id);
  }
  async verify(proof: MembershipProof, expectedId: string): Promise<boolean> {
    return verifyCurrentMembership(proof, await this.chain.currentRoot(), expectedId);
  }
}
