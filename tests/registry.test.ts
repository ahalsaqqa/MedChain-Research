import { Field } from 'o1js';
import { syntheticRecords } from '../src/fixtures.js';
import { recordCommitment } from '../src/records.js';
import type { MedicineRecord } from '../src/records.js';
import { buildSnapshot } from '../src/registry.js';

describe('registrar snapshot', () => {
  test('rejects duplicate record IDs', () => {
    const record = syntheticRecords(1, 20261014)[0];
    expect(() => buildSnapshot([{ record, salt: Field(1) }, { record: { ...record, quantity: 2 }, salt: Field(2) }])).toThrow(/duplicate/);
  });

  test('rejects capacity overflow before building a tree', () => {
    const entries = syntheticRecords(1025, 1).map((record: MedicineRecord) => ({ record, salt: Field(1) }));
    expect(() => buildSnapshot(entries)).toThrow(/1024|1,024|capacity/);
  });

  test('last legal leaf yields index 1023 and a witness for the published root', () => {
    const entries = syntheticRecords(1024, 1).map((record: MedicineRecord) => ({ record, salt: Field(1) }));
    const snapshot = buildSnapshot(entries);
    const last = snapshot.lookup(entries[1023].record.recordId);
    expect(last.index).toBe(1023n);
    expect(snapshot.witness(last.record.recordId).calculateIndex().toBigInt()).toBe(1023n);
    expect(snapshot.witness(last.record.recordId).calculateRoot(last.commitment).equals(snapshot.root).toBoolean()).toBe(true);
  });

  test('owns caller inputs and returns defensive lookup records and fresh witnesses', () => {
    const record = syntheticRecords(1, 20261014)[0];
    const original = { ...record };
    const entries = [{ record, salt: Field(19) }];
    const snapshot = buildSnapshot(entries);
    const root = snapshot.root.toString();
    const witness = snapshot.witness(original.recordId);
    record.quantity += 1;
    entries.splice(0);
    const found = snapshot.lookup(original.recordId);
    expect(found.record).toEqual(original);
    expect(found.index).toBe(0n);
    expect(found.commitment.equals(recordCommitment(original, Field(19))).toBoolean()).toBe(true);
    found.record.recordId = 'changed';
    witness.path[0] = Field(999);
    expect(witness.calculateRoot(found.commitment).equals(snapshot.root).toBoolean()).toBe(false);
    expect(snapshot.lookup(original.recordId).record).toEqual(original);
    expect(snapshot.root.toString()).toBe(root);
    expect(snapshot.witness(original.recordId).calculateRoot(found.commitment).equals(snapshot.root).toBoolean()).toBe(true);
    expect(() => snapshot.lookup('changed')).toThrow(/not found|unknown/);
  });

  test('rejects malformed records and unknown witness/lookup IDs', () => {
    const record = syntheticRecords(1, 1)[0];
    expect(() => buildSnapshot([{ record: { ...record, quantity: 0 }, salt: Field(1) }])).toThrow(/quantity/);
    const snapshot = buildSnapshot([]);
    expect(() => snapshot.lookup(record.recordId)).toThrow(/not found|unknown/);
    expect(() => snapshot.witness(record.recordId)).toThrow(/not found|unknown/);
  });
});
