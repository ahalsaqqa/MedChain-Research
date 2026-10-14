import { Field, Struct, ZkProgram } from 'o1js';
import {
  EncodedRecord,
  encodeRecord,
  encodedRecordCommitment,
  hashIdentifier,
} from './records.js';
import { RecordWitness, RegistrySnapshot } from './registry.js';
export class MembershipQuery extends Struct({
  root: Field,
  requestedRecordIdHash: Field,
}) {}
export const MembershipProgram = ZkProgram({
  name: 'MedChainMembershipV1',
  publicInput: MembershipQuery,
  methods: {
    proveRecord: {
      privateInputs: [EncodedRecord, Field, RecordWitness],
      async method(
        query: MembershipQuery,
        encodedRecord: EncodedRecord,
        salt: Field,
        witness: RecordWitness
      ) {
        encodedRecord.recordIdHash.assertEquals(
          query.requestedRecordIdHash,
          'requested record ID must match private record'
        );
        witness
          .calculateRoot(encodedRecordCommitment(encodedRecord, salt))
          .assertEquals(query.root, 'membership root must match');
      },
    },
  },
});
export class MembershipProof extends ZkProgram.Proof(MembershipProgram) {}
export async function proveMembership(
  snapshot: RegistrySnapshot,
  id: string
): Promise<MembershipProof> {
  const entry = snapshot.lookup(id);
  const { proof } = await MembershipProgram.proveRecord(
    new MembershipQuery({
      root: snapshot.root,
      requestedRecordIdHash: hashIdentifier(id),
    }),
    encodeRecord(entry.record),
    entry.salt,
    snapshot.witness(id)
  );
  return proof;
}
/** Cryptography plus caller-supplied current root and requested ID; never trust proof inputs as anchors. */
export async function verifyCurrentMembership(
  proof: MembershipProof,
  expectedRoot: Field,
  expectedId: string
): Promise<boolean> {
  // The SDK deliberately returns true for verify() in mock mode; fail closed here.
  if (!MembershipProgram.proofsEnabled) return false;
  try {
    if (!(await MembershipProgram.verify(proof))) return false;
    return (
      proof.publicInput.root.equals(expectedRoot).toBoolean() &&
      proof.publicInput.requestedRecordIdHash
        .equals(hashIdentifier(expectedId))
        .toBoolean()
    );
  } catch {
    return false;
  }
}
