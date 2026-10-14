import { randomBytes } from 'node:crypto';
import { Encoding, Field, Poseidon, Struct } from 'o1js';

export interface MedicineRecord {
  recordId: string;
  medicineId: string;
  batchId: string;
  manufacturerId: string;
  distributorId: string;
  pharmacyId: string;
  quantity: number;
  occurredAt: number;
  expiresAt: number;
}

const IDENTIFIER_FIELDS = [
  'recordId', 'medicineId', 'batchId', 'manufacturerId', 'distributorId', 'pharmacyId',
] as const;
const RECORD_FIELDS = [...IDENTIFIER_FIELDS, 'quantity', 'occurredAt', 'expiresAt'] as const;
export const IDENTIFIER_HASH_DOMAIN = 'MedChain:id:v1';
export const RECORD_COMMITMENT_DOMAIN = 'MedChain:record:v1';

function validateIdentifier(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${name} must be a non-empty UTF-8 string`);
  }
  // TextEncoder replaces lone surrogates: reject them before UTF-8 encoding.
  if (!value.isWellFormed()) throw new Error(`${name} contains invalid UTF encoding`);
  if (Buffer.byteLength(value, 'utf8') > 128) throw new Error(`${name} exceeds 128 UTF-8 bytes`);
}

/** Host validation; these semantic constraints are not membership-circuit claims. */
export function validateRecord(value: unknown): MedicineRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('record must be an object with exactly nine fields');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== RECORD_FIELDS.length || keys.some((key) => !RECORD_FIELDS.includes(key as typeof RECORD_FIELDS[number]))) {
    throw new Error('record has missing or unknown fields');
  }
  const input = value as Record<string, unknown>;
  for (const key of RECORD_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor)) throw new Error(`${key} must be an own data field`);
  }
  for (const key of IDENTIFIER_FIELDS) validateIdentifier(input[key], key);
  if (!Number.isSafeInteger(input.quantity) || (input.quantity as number) <= 0) {
    throw new Error('quantity must be a positive safe integer');
  }
  for (const key of ['occurredAt', 'expiresAt'] as const) {
    if (!Number.isSafeInteger(input[key]) || (input[key] as number) < 0) {
      throw new Error(`${key} must be a nonnegative safe integer Unix second`);
    }
  }
  if ((input.expiresAt as number) <= (input.occurredAt as number)) {
    throw new Error('expiresAt must be greater than occurredAt');
  }
  return Object.fromEntries(RECORD_FIELDS.map((key) => [key, input[key]])) as unknown as MedicineRecord;
}

export function canonicalRecord(record: MedicineRecord): string {
  return JSON.stringify(validateRecord(record));
}

export class EncodedRecord extends Struct({
  recordIdHash: Field,
  medicineIdHash: Field,
  batchIdHash: Field,
  manufacturerIdHash: Field,
  distributorIdHash: Field,
  pharmacyIdHash: Field,
  quantity: Field,
  occurredAt: Field,
  expiresAt: Field,
}) {}

export function hashIdentifier(value: string): Field {
  validateIdentifier(value, 'identifier');
  // SDK encoding uses UTF-8 and a terminator, preserving trailing zero bytes.
  return Poseidon.hashWithPrefix(IDENTIFIER_HASH_DOMAIN, Encoding.stringToFields(value));
}

export function encodeRecord(record: MedicineRecord): EncodedRecord {
  const valid = validateRecord(record);
  return new EncodedRecord({
    recordIdHash: hashIdentifier(valid.recordId),
    medicineIdHash: hashIdentifier(valid.medicineId),
    batchIdHash: hashIdentifier(valid.batchId),
    manufacturerIdHash: hashIdentifier(valid.manufacturerId),
    distributorIdHash: hashIdentifier(valid.distributorId),
    pharmacyIdHash: hashIdentifier(valid.pharmacyId),
    quantity: Field(valid.quantity),
    occurredAt: Field(valid.occurredAt),
    expiresAt: Field(valid.expiresAt),
  });
}

export function recordCommitment(record: MedicineRecord, salt: Field): Field {
  return encodedRecordCommitment(encodeRecord(record), salt);
}

export function encodedRecordCommitment(encoded: EncodedRecord, salt: Field): Field {
  return Poseidon.hashWithPrefix(RECORD_COMMITMENT_DOMAIN, [...EncodedRecord.toFields(encoded), salt]);
}

/** Independent, unseeded 128-bit salt; never include this value in public logs. */
export function randomSalt(): Field {
  return Field(BigInt(`0x${randomBytes(16).toString('hex')}`));
}
