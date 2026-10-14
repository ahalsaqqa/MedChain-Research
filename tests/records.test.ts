import { Field } from 'o1js';
import {
  EncodedRecord, canonicalRecord, encodeRecord, hashIdentifier,
  randomSalt, recordCommitment, validateRecord,
} from '../src/records.js';
import { syntheticRecords } from '../src/fixtures.js';

const record = {
  recordId: 'record-1', medicineId: 'medicine-2', batchId: 'batch-3',
  manufacturerId: 'manufacturer-4', distributorId: 'distributor-5',
  pharmacyId: 'pharmacy-6', quantity: 7, occurredAt: 100, expiresAt: 200,
};
const identifiers = ['recordId', 'medicineId', 'batchId', 'manufacturerId', 'distributorId', 'pharmacyId'] as const;

describe('record validation and canonical encoding', () => {
  test('accepts exact schema and preserves valid Unicode without normalization', () => {
    const input = { ...record, recordId: 'e\u0301💊' };
    expect(validateRecord(input)).toEqual(input);
    expect(validateRecord(record)).toEqual(record);
  });

  test('canonical serialization has the documented field order regardless of input order', () => {
    const { expiresAt, ...rest } = record;
    expect(canonicalRecord({ expiresAt, ...rest })).toBe('{"recordId":"record-1","medicineId":"medicine-2","batchId":"batch-3","manufacturerId":"manufacturer-4","distributorId":"distributor-5","pharmacyId":"pharmacy-6","quantity":7,"occurredAt":100,"expiresAt":200}');
  });

  test('rejects null, arrays, unknown fields, missing fields and symbol keys', () => {
    for (const input of [null, [], { ...record, extra: true }, { ...record, [Symbol('extra')]: true }]) {
      expect(() => validateRecord(input)).toThrow();
    }
    for (const field of Object.keys(record)) {
      const input: Record<string, unknown> = { ...record };
      delete input[field];
      expect(() => validateRecord(input)).toThrow();
    }
  });

  test.each(identifiers)('rejects empty, non-string, ill-formed UTF-16 or oversized %s', (field) => {
    for (const value of ['', 12, String.fromCharCode(0xd800), String.fromCharCode(0xdc00), '💊'.repeat(33)]) {
      expect(() => validateRecord({ ...record, [field]: value })).toThrow();
    }
    expect(() => validateRecord({ ...record, [field]: String.fromCharCode(0xd800) })).toThrow(/UTF/);
    expect(validateRecord({ ...record, [field]: '💊'.repeat(32) })[field]).toBe('💊'.repeat(32));
  });

  test.each([0, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, '1'])('rejects invalid quantity %s', (quantity) => {
    expect(() => validateRecord({ ...record, quantity })).toThrow(/quantity/);
  });

  test.each(['occurredAt', 'expiresAt'] as const)('rejects invalid %s', (field) => {
    for (const value of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, '100']) {
      expect(() => validateRecord({ ...record, [field]: value })).toThrow(new RegExp(field));
    }
  });

  test('allows safe bounds and zero occurrence but rejects unordered expiry', () => {
    expect(validateRecord({ ...record, quantity: Number.MAX_SAFE_INTEGER, occurredAt: 0, expiresAt: Number.MAX_SAFE_INTEGER }).occurredAt).toBe(0);
    for (const expiresAt of [99, 100]) expect(() => validateRecord({ ...record, expiresAt })).toThrow(/expiresAt/);
  });

  test('encodes all nine fields in canonical order', () => {
    const fields = EncodedRecord.toFields(encodeRecord(record)).map((field: Field) => field.toString());
    expect(fields).toEqual([
      ...identifiers.map((key) => hashIdentifier(record[key]).toString()), '7', '100', '200',
    ]);
    expect(hashIdentifier('e\u0301').equals(hashIdentifier('é')).toBoolean()).toBe(false);
    expect(hashIdentifier('a').equals(hashIdentifier('a\0')).toBoolean()).toBe(false);
    expect(() => hashIdentifier(String.fromCharCode(0xd800))).toThrow(/UTF/);
    expect(() => encodeRecord({ ...record, quantity: 0 })).toThrow(/quantity/);
  });
});

describe('salted commitments', () => {
  test('is deterministic with the same record and salt and binds every field and salt', () => {
    const salt = randomSalt();
    const commitment = recordCommitment(record, salt);
    expect(recordCommitment({ ...record }, salt).equals(commitment).toBoolean()).toBe(true);
    for (const key of identifiers) {
      expect(recordCommitment({ ...record, [key]: record[key] + 'x' }, salt).equals(commitment).toBoolean()).toBe(false);
    }
    for (const key of ['quantity', 'occurredAt', 'expiresAt'] as const) {
      expect(recordCommitment({ ...record, [key]: record[key] + 1 }, salt).equals(commitment).toBoolean()).toBe(false);
    }
    expect(recordCommitment(record, salt.add(1)).equals(commitment).toBoolean()).toBe(false);
    expect(() => recordCommitment({ ...record, quantity: 0 }, Field(1))).toThrow(/quantity/);
  });

  test('generates independent 128-bit salts', () => {
    const salts = Array.from({ length: 16 }, () => randomSalt().toBigInt());
    expect(new Set(salts).size).toBe(16);
    expect(salts.every((salt) => salt >= 0n && salt < 2n ** 128n)).toBe(true);
  });
});

describe('synthetic generator v1', () => {
  test('reproduces every schema-valid record and changes with seed', () => {
    const records = syntheticRecords(100, 20261014);
    expect(records).toHaveLength(100);
    expect(records).toEqual(syntheticRecords(100, 20261014));
    expect(records).not.toEqual(syntheticRecords(100, 20261015));
    expect(new Set(records.map((value: typeof record) => value.recordId)).size).toBe(100);
    for (const value of records) expect(validateRecord(value)).toEqual(value);
    expect(syntheticRecords(0, 1)).toEqual([]);
  });

  test('rejects invalid counts and seeds', () => {
    for (const size of [-1, 1.5, NaN, Number.MAX_SAFE_INTEGER + 1]) expect(() => syntheticRecords(size, 1)).toThrow();
    for (const seed of [1.5, NaN, Number.MAX_SAFE_INTEGER + 1]) expect(() => syntheticRecords(1, seed)).toThrow();
  });
});
