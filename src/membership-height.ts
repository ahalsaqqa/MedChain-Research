import { Field, MerkleWitness, ZkProgram } from 'o1js';
import { EncodedRecord, encodedRecordCommitment } from './records.js';
import { MembershipQuery } from './membership.js';

export const MIN_TREE_HEIGHT = 2;
export const MAX_TREE_HEIGHT = 256;

/**
 * The MembershipProgram statement at a configurable Merkle tree height, for the tree-height
 * experiment only. MembershipProgram itself stays at height 11 and is not affected.
 */
export function membershipProgramForHeight(height: number) {
  if (!Number.isInteger(height) || height < MIN_TREE_HEIGHT || height > MAX_TREE_HEIGHT) {
    throw new Error(`tree height must be an integer in [${MIN_TREE_HEIGHT}, ${MAX_TREE_HEIGHT}]`);
  }
  class HeightWitness extends MerkleWitness(height) {}
  const program = ZkProgram({
    name: `MedChainMembershipH${height}`,
    publicInput: MembershipQuery,
    methods: {
      proveRecord: {
        privateInputs: [EncodedRecord, Field, HeightWitness],
        async method(query: MembershipQuery, encodedRecord: EncodedRecord, salt: Field, witness: HeightWitness) {
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
  return { Witness: HeightWitness, program };
}
