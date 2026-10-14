import { Field, Provable } from 'o1js';
import { syntheticRecords } from '../src/fixtures.js';
import { EncodedRecord, encodeRecord, hashIdentifier } from '../src/records.js';
import { buildSnapshot, RecordWitness } from '../src/registry.js';
import {
  MembershipProgram,
  MembershipProof,
  MembershipQuery,
  proveMembership,
  verifyCurrentMembership,
} from '../src/membership.js';

// These tests evaluate circuit constraints, never cryptographic verification.
describe('membership constraints (proof generation disabled; constraint evaluation only)', () => {
  const records = syntheticRecords(2, 20261014);
  const snapshot = buildSnapshot(
    records.map((record, i) => ({ record, salt: Field(11 + i) }))
  );
  const id = records[0].recordId;
  const entry = snapshot.lookup(id);
  const query = new MembershipQuery({
    root: snapshot.root,
    requestedRecordIdHash: hashIdentifier(id),
  });
  async function check(
    encoded = encodeRecord(entry.record),
    salt = entry.salt,
    witness = snapshot.witness(id),
    request = query
  ) {
    await Provable.runAndCheck(async () => {
      await MembershipProgram.rawMethods.proveRecord(
        Provable.witness(MembershipQuery, () => request),
        Provable.witness(EncodedRecord, () => encoded),
        Provable.witness(Field, () => salt),
        Provable.witness(RecordWitness, () => witness)
      );
    });
  }
  test('accepts the registered encoded record, salt and witness', async () => {
    await expect(check()).resolves.toBeUndefined();
  });
  test('rejects a changed encoded quantity at the root constraint', async () => {
    const encoded = encodeRecord(entry.record);
    encoded.quantity = encoded.quantity.add(1);
    await expect(check(encoded)).rejects.toThrow(/membership root/);
  });
  test('rejects a changed salt at the root constraint', async () => {
    await expect(check(undefined, entry.salt.add(1))).rejects.toThrow(
      /membership root/
    );
  });
  test('rejects another record witness at the root constraint', async () => {
    await expect(
      check(undefined, undefined, snapshot.witness(records[1].recordId))
    ).rejects.toThrow(/membership root/);
  });
  test('rejects record B public query for private record A at the ID constraint', async () => {
    await expect(
      check(
        undefined,
        undefined,
        undefined,
        new MembershipQuery({
          root: snapshot.root,
          requestedRecordIdHash: hashIdentifier(records[1].recordId),
        })
      )
    ).rejects.toThrow(/requested record ID/);
  });
  test('refuses mock proof verification even when public inputs match', async () => {
    const mock = await MembershipProof.dummy(query, undefined, 0);
    MembershipProgram.setProofsEnabled(false);
    try {
      expect(await verifyCurrentMembership(mock, snapshot.root, id)).toBe(
        false
      );
    } finally {
      MembershipProgram.setProofsEnabled(true);
    }
  });
  test('rejects an unregistered ID before attempting proof generation', async () => {
    await expect(proveMembership(snapshot, 'unknown')).rejects.toThrow(
      /not found/
    );
  });
});
