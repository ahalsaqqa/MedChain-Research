import { Field, MerkleTree, MerkleWitness } from 'o1js';
import { recordCommitment, validateRecord } from './records.js';
import type { MedicineRecord } from './records.js';

export const RECORD_TREE_HEIGHT = 11;
export const RECORD_CAPACITY = 1024;
export class RecordWitness extends MerkleWitness(RECORD_TREE_HEIGHT) {}

export interface RegistryEntry {
  record: MedicineRecord;
  salt: Field;
}

export interface RegisteredRecord extends RegistryEntry {
  index: bigint;
  commitment: Field;
}

/** A trusted registrar's immutable snapshot. Its mutable SDK tree is never exposed. */
export class RegistrySnapshot {
  #tree: MerkleTree;
  #entries = new Map<string, RegisteredRecord>();
  #root: bigint;

  constructor(entries: readonly RegistryEntry[]) {
    if (entries.length > RECORD_CAPACITY) throw new Error('registry capacity is 1024 records');
    this.#tree = new MerkleTree(RECORD_TREE_HEIGHT);
    if (this.#tree.leafCount !== BigInt(RECORD_CAPACITY)) {
      throw new Error('SDK tree capacity differs from the approved 1024 leaves');
    }
    entries.forEach((entry, offset) => {
      const record = validateRecord(entry.record);
      if (this.#entries.has(record.recordId)) throw new Error('duplicate recordId');
      const salt = Field(entry.salt.toBigInt());
      const commitment = recordCommitment(record, salt);
      const index = BigInt(offset);
      this.#tree.setLeaf(index, commitment);
      this.#entries.set(record.recordId, { index, record, salt, commitment });
    });
    this.#root = this.#tree.getRoot().toBigInt();
  }

  get root(): Field {
    return Field(this.#root);
  }

  lookup(id: string): RegisteredRecord {
    const entry = this.#entries.get(id);
    if (!entry) throw new Error('recordId not found in snapshot');
    return {
      index: entry.index, record: { ...entry.record },
      salt: Field(entry.salt.toBigInt()), commitment: Field(entry.commitment.toBigInt()),
    };
  }

  witness(id: string): RecordWitness {
    const entry = this.#entries.get(id);
    if (!entry) throw new Error('recordId not found in snapshot');
    return new RecordWitness(this.#tree.getWitness(entry.index).map(({ isLeft, sibling }) => ({
      isLeft, sibling: Field(sibling.toBigInt()),
    })));
  }
}

export function buildSnapshot(entries: readonly RegistryEntry[]): RegistrySnapshot {
  return new RegistrySnapshot(entries);
}
