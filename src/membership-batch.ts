import { Field, Poseidon, Provable, Struct, ZkProgram } from 'o1js';
import { EncodedRecord, encodedRecordCommitment } from './records.js';
import { RecordWitness } from './registry.js';

export const MAX_BATCH_SIZE = 256;

/** Public input of a batch proof: one root and one hash binding the ordered list of requested IDs. */
export class BatchQuery extends Struct({
  root: Field,
  requestedIdsHash: Field,
}) {}

/** Ordered binding of requested identifier hashes; the verifier recomputes it from its own request. */
export function requestedIdsHash(idHashes: Field[]): Field {
  return Poseidon.hash(idHashes);
}

/**
 * One proof that k encoded records are all members of the same height-11 registry root and that
 * their identifier hashes are exactly the requested ordered list. Batch-size experiment only;
 * MembershipProgram (one record per proof) is unchanged.
 */
export function membershipBatchProgram(batchSize: number) {
  if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
    throw new Error(`batch size must be an integer in [1, ${MAX_BATCH_SIZE}]`);
  }
  const Records = Provable.Array(EncodedRecord, batchSize);
  const Salts = Provable.Array(Field, batchSize);
  const Witnesses = Provable.Array(RecordWitness, batchSize);
  const program = ZkProgram({
    name: `MedChainMembershipBatch${batchSize}`,
    publicInput: BatchQuery,
    methods: {
      proveBatch: {
        privateInputs: [Records, Salts, Witnesses],
        async method(query: BatchQuery, records: EncodedRecord[], salts: Field[], witnesses: RecordWitness[]) {
          for (let i = 0; i < batchSize; i++) {
            witnesses[i]
              .calculateRoot(encodedRecordCommitment(records[i], salts[i]))
              .assertEquals(query.root, 'every batch member must be under the root');
          }
          requestedIdsHash(records.map((r) => r.recordIdHash))
            .assertEquals(query.requestedIdsHash, 'batch must match the requested ordered IDs');
        },
      },
    },
  });
  return { program, Records, Salts, Witnesses };
}
