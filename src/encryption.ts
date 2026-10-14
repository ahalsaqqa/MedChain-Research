import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { Field } from 'o1js';
import {
  MedicineRecord,
  canonicalRecord,
  hashIdentifier,
  recordCommitment,
  validateRecord,
} from './records.js';

export interface EncryptedEnvelope {
  version: 1;
  algorithm: 'AES-256-GCM';
  keyVersion: number;
  requestedRecordIdHash: string;
  recordCommitment: string;
  nonce: string;
  ciphertext: string;
  tag: string;
}

const ENVELOPE_FIELDS = [
  'version',
  'algorithm',
  'keyVersion',
  'requestedRecordIdHash',
  'recordCommitment',
  'nonce',
  'ciphertext',
  'tag',
] as const;

function exactObject(
  value: unknown,
  keys: readonly string[],
  label: string
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  const own = Reflect.ownKeys(value);
  if (
    own.length !== keys.length ||
    own.some((key) => typeof key !== 'string' || !keys.includes(key))
  )
    throw new Error(`${label} has missing or unknown fields`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !('value' in descriptor))
      throw new Error(`${label} requires own data fields`);
  }
  return value as Record<string, unknown>;
}

function requireBuffer(value: Buffer, label: string, length?: number): void {
  if (!Buffer.isBuffer(value)) throw new Error(`${label} must be a Buffer`);
  if (length !== undefined && value.length !== length)
    throw new Error(`${label} must contain ${length} bytes`);
}

function canonicalInteger(
  value: unknown,
  limit: bigint,
  label: string
): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value))
    throw new Error(`${label} must be a canonical decimal string`);
  const integer = BigInt(value);
  if (integer.toString() !== value || integer >= limit)
    throw new Error(`${label} is outside its canonical range`);
  return integer;
}

function keyVersion(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1)
    throw new Error('keyVersion must be a positive safe integer');
}

function base64(value: unknown, label: string, length?: number): Buffer {
  if (typeof value !== 'string')
    throw new Error(`${label} must be canonical base64`);
  const bytes = Buffer.from(value, 'base64');
  if (
    bytes.toString('base64') !== value ||
    (length === undefined ? bytes.length === 0 : bytes.length !== length)
  )
    throw new Error(`${label} has invalid base64 or byte length`);
  return bytes;
}

export function validateEnvelope(value: unknown): EncryptedEnvelope {
  const input = exactObject(value, ENVELOPE_FIELDS, 'envelope');
  if (input.version !== 1) throw new Error('unsupported envelope version');
  if (input.algorithm !== 'AES-256-GCM')
    throw new Error('unsupported envelope algorithm');
  keyVersion(input.keyVersion);
  canonicalInteger(input.requestedRecordIdHash, Field.ORDER, 'ID hash');
  canonicalInteger(input.recordCommitment, Field.ORDER, 'record commitment');
  base64(input.nonce, 'nonce', 12);
  base64(input.ciphertext, 'ciphertext');
  base64(input.tag, 'tag', 16);
  return Object.fromEntries(
    ENVELOPE_FIELDS.map((key) => [key, input[key]])
  ) as unknown as EncryptedEnvelope;
}

function metadata(
  envelope: Pick<
    EncryptedEnvelope,
    | 'version'
    | 'algorithm'
    | 'keyVersion'
    | 'requestedRecordIdHash'
    | 'recordCommitment'
  >
): Buffer {
  return Buffer.from(
    JSON.stringify({
      version: envelope.version,
      algorithm: envelope.algorithm,
      keyVersion: envelope.keyVersion,
      requestedRecordIdHash: envelope.requestedRecordIdHash,
      recordCommitment: envelope.recordCommitment,
    }),
    'utf8'
  );
}

/** AES-only primitive for pre-encoded benchmark inputs. Production callers use encryptRecord. */
export function sealPayload(
  plaintext: Buffer,
  key: Buffer,
  nonce: Buffer,
  aad: Buffer
): { ciphertext: Buffer; tag: Buffer } {
  requireBuffer(plaintext, 'plaintext');
  requireBuffer(key, 'key', 32);
  requireBuffer(nonce, 'nonce', 12);
  requireBuffer(aad, 'aad');
  const cipher = createCipheriv('aes-256-gcm', key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { ciphertext, tag: cipher.getAuthTag() };
}

/** AES-only primitive; rejects authentication failure without returning partial plaintext. */
export function openPayload(
  ciphertext: Buffer,
  tag: Buffer,
  key: Buffer,
  nonce: Buffer,
  aad: Buffer
): Buffer {
  requireBuffer(ciphertext, 'ciphertext');
  requireBuffer(tag, 'tag', 16);
  requireBuffer(key, 'key', 32);
  requireBuffer(nonce, 'nonce', 12);
  requireBuffer(aad, 'aad');
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, nonce, {
      authTagLength: 16,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('payload authentication failed');
  }
}

export function encryptRecord(
  record: MedicineRecord,
  salt: Field,
  key: Buffer,
  version: number
): EncryptedEnvelope {
  const valid = validateRecord(record);
  const saltString = salt.toString();
  canonicalInteger(saltString, 2n ** 128n, 'salt');
  keyVersion(version);
  requireBuffer(key, 'key', 32);
  const header = {
    version: 1 as const,
    algorithm: 'AES-256-GCM' as const,
    keyVersion: version,
    requestedRecordIdHash: hashIdentifier(valid.recordId).toString(),
    recordCommitment: recordCommitment(valid, salt).toString(),
  };
  const nonce = randomBytes(12);
  const plaintext = Buffer.from(
    `{"record":${canonicalRecord(valid)},"salt":${JSON.stringify(saltString)}}`,
    'utf8'
  );
  const sealed = sealPayload(plaintext, key, nonce, metadata(header));
  return {
    ...header,
    nonce: nonce.toString('base64'),
    ciphertext: sealed.ciphertext.toString('base64'),
    tag: sealed.tag.toString('base64'),
  };
}

export function decryptRecord(
  envelope: unknown,
  key: Buffer,
  expected: { id: string; commitment: Field }
): { record: MedicineRecord; salt: Field } {
  const valid = validateEnvelope(envelope);
  const expectedHash = hashIdentifier(expected.id).toString();
  if (expectedHash !== valid.requestedRecordIdHash)
    throw new Error('expected record ID mismatch');
  if (expected.commitment.toString() !== valid.recordCommitment)
    throw new Error('expected record commitment mismatch');
  const plaintext = openPayload(
    base64(valid.ciphertext, 'ciphertext'),
    base64(valid.tag, 'tag', 16),
    key,
    base64(valid.nonce, 'nonce', 12),
    metadata(valid)
  );
  let decoded: unknown;
  try {
    decoded = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(plaintext)
    );
  } catch {
    throw new Error('invalid encrypted payload encoding');
  }
  const payload = exactObject(decoded, ['record', 'salt'], 'payload');
  const record = validateRecord(payload.record);
  const salt = Field(canonicalInteger(payload.salt, 2n ** 128n, 'salt'));
  if (
    record.recordId !== expected.id ||
    hashIdentifier(record.recordId).toString() !== valid.requestedRecordIdHash
  )
    throw new Error('payload record ID mismatch');
  if (recordCommitment(record, salt).toString() !== valid.recordCommitment)
    throw new Error('payload record commitment mismatch');
  const canonical = Buffer.from(
    `{"record":${canonicalRecord(record)},"salt":${JSON.stringify(
      salt.toString()
    )}}`,
    'utf8'
  );
  if (!canonical.equals(plaintext))
    throw new Error('payload must use canonical serialization');
  return { record, salt };
}

export function serializeEnvelope(envelope: EncryptedEnvelope): Buffer {
  return Buffer.from(JSON.stringify(validateEnvelope(envelope)), 'utf8');
}
