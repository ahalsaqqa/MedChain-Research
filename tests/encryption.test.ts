import { randomBytes } from 'node:crypto';
import { Field } from 'o1js';
import {
  encryptRecord,
  decryptRecord,
  serializeEnvelope,
  sealPayload,
  openPayload,
} from '../src/encryption.js';
import { hashIdentifier, recordCommitment } from '../src/records.js';

const record = {
  recordId: 'record-1',
  medicineId: 'medicine-2',
  batchId: 'batch-3',
  manufacturerId: 'maker-4',
  distributorId: 'distributor-5',
  pharmacyId: 'pharmacy-6',
  quantity: 7,
  occurredAt: 100,
  expiresAt: 200,
};
const salt = Field(123);
const key = randomBytes(32);
const commitment = recordCommitment(record, salt);
const expected = { id: record.recordId, commitment };
const aad = (envelope: ReturnType<typeof encryptRecord>) =>
  Buffer.from(
    JSON.stringify({
      version: envelope.version,
      algorithm: envelope.algorithm,
      keyVersion: envelope.keyVersion,
      requestedRecordIdHash: envelope.requestedRecordIdHash,
      recordCommitment: envelope.recordCommitment,
    })
  );

describe('authenticated record encryption', () => {
  test('round trips the complete record and exact salt with a fresh nonce each time', () => {
    const first = encryptRecord(record, salt, key, 1);
    const second = encryptRecord(record, salt, key, 1);
    expect(decryptRecord(first, key, expected)).toEqual({ record, salt });
    expect(first.nonce).not.toBe(second.nonce);
    expect(Object.keys(first)).toEqual([
      'version',
      'algorithm',
      'keyVersion',
      'requestedRecordIdHash',
      'recordCommitment',
      'nonce',
      'ciphertext',
      'tag',
    ]);
    expect(Buffer.from(first.nonce, 'base64')).toHaveLength(12);
    expect(Buffer.from(first.tag, 'base64')).toHaveLength(16);
  });

  test('serializes canonical metadata and envelope independent of property order', () => {
    const envelope = encryptRecord(record, salt, key, 1);
    const reversed = Object.fromEntries(
      Object.entries(envelope).reverse()
    ) as typeof envelope;
    expect(serializeEnvelope(reversed)).toEqual(
      Buffer.from(JSON.stringify(envelope))
    );
    expect(
      decryptRecord(
        JSON.parse(serializeEnvelope(reversed).toString()),
        key,
        expected
      )
    ).toEqual({ record, salt });
  });

  test.each([
    'version',
    'algorithm',
    'keyVersion',
    'requestedRecordIdHash',
    'recordCommitment',
    'nonce',
    'ciphertext',
    'tag',
  ])('rejects tampered %s', (field) => {
    const envelope = encryptRecord(record, salt, key, 1);
    const changes: Record<string, unknown> = {
      version: 2,
      algorithm: 'AES-128-GCM',
      keyVersion: 2,
      requestedRecordIdHash: '1',
      recordCommitment: '1',
    };
    if (field in changes)
      expect(() =>
        decryptRecord({ ...envelope, [field]: changes[field] }, key, expected)
      ).toThrow();
    else {
      const bytes = Buffer.from(
        envelope[field as 'nonce' | 'ciphertext' | 'tag'],
        'base64'
      );
      bytes[0] ^= 1;
      expect(() =>
        decryptRecord(
          { ...envelope, [field]: bytes.toString('base64') },
          key,
          expected
        )
      ).toThrow();
    }
  });

  test('binds independently supplied ID and registered commitment and rejects wrong key', () => {
    const envelope = encryptRecord(record, salt, key, 1);
    expect(() =>
      decryptRecord(envelope, key, { ...expected, id: 'another-id' })
    ).toThrow(/ID/);
    expect(() =>
      decryptRecord(envelope, key, {
        ...expected,
        commitment: commitment.add(1),
      })
    ).toThrow(/commitment/);
    expect(() => decryptRecord(envelope, randomBytes(32), expected)).toThrow(
      /authentic/i
    );
  });

  test('rejects authenticated payload B carrying metadata and expected query A', () => {
    const envelope = encryptRecord(record, salt, key, 1);
    const otherRecord = { ...record, recordId: 'record-B' };
    const sealed = sealPayload(
      Buffer.from(JSON.stringify({ record: otherRecord, salt: '123' })),
      key,
      Buffer.from(envelope.nonce, 'base64'),
      aad(envelope)
    );
    expect(() =>
      decryptRecord(
        {
          ...envelope,
          ciphertext: sealed.ciphertext.toString('base64'),
          tag: sealed.tag.toString('base64'),
        },
        key,
        expected
      )
    ).toThrow(/ID/);
  });

  test('rejects authenticated payload with a different commitment even when its ID agrees', () => {
    const envelope = encryptRecord(record, salt, key, 1);
    const sealed = sealPayload(
      Buffer.from(
        JSON.stringify({ record: { ...record, quantity: 8 }, salt: '123' })
      ),
      key,
      Buffer.from(envelope.nonce, 'base64'),
      aad(envelope)
    );
    expect(() =>
      decryptRecord(
        {
          ...envelope,
          ciphertext: sealed.ciphertext.toString('base64'),
          tag: sealed.tag.toString('base64'),
        },
        key,
        expected
      )
    ).toThrow(/commitment/);
  });

  test('rejects missing/extra metadata, accessors, symbols and wrong object types', () => {
    const envelope = encryptRecord(record, salt, key, 1);
    const { tag, ...missing } = envelope;
    for (const bad of [
      null,
      [],
      'text',
      missing,
      { ...envelope, extra: 1 },
      { ...envelope, [Symbol('extra')]: 1 },
      Object.defineProperty({ ...envelope }, 'tag', { get: () => tag }),
    ]) {
      expect(() => decryptRecord(bad, key, expected)).toThrow(/envelope/);
    }
  });

  test.each([
    ['nonce', 'AA=='],
    ['nonce', '!!!!!!!!!!!!!!!!'],
    ['nonce', 'AAAAAAAAAAAAAAAA\n'],
    ['tag', 'AA=='],
    ['tag', 'AAAAAAAAAAAAAAAAAAAAAB=='],
    ['ciphertext', ''],
    ['ciphertext', '%%%'],
    ['requestedRecordIdHash', '01'],
    ['recordCommitment', '-1'],
    ['recordCommitment', Field.ORDER.toString()],
    ['keyVersion', 0],
    ['keyVersion', 1.5],
    ['keyVersion', Number.MAX_SAFE_INTEGER + 1],
  ])('rejects malformed %s = %s', (field, value) => {
    const bad = { ...encryptRecord(record, salt, key, 1), [field]: value };
    expect(() => decryptRecord(bad, key, expected)).toThrow();
    expect(() =>
      serializeEnvelope(bad as ReturnType<typeof encryptRecord>)
    ).toThrow();
  });

  test.each(['01', '-1', (2n ** 128n).toString(), 123])(
    'rejects authenticated noncanonical/out-of-range salt %s',
    (invalidSalt) => {
      const envelope = encryptRecord(record, salt, key, 1);
      const sealed = sealPayload(
        Buffer.from(JSON.stringify({ record, salt: invalidSalt })),
        key,
        Buffer.from(envelope.nonce, 'base64'),
        aad(envelope)
      );
      expect(() =>
        decryptRecord(
          {
            ...envelope,
            ciphertext: sealed.ciphertext.toString('base64'),
            tag: sealed.tag.toString('base64'),
          },
          key,
          expected
        )
      ).toThrow(/salt/);
    }
  );

  test.each([
    null,
    [],
    { record },
    { record, salt: '123', extra: true },
    { record: { ...record, quantity: 0 }, salt: '123' },
  ])('rejects invalid authenticated payload %#', (payload) => {
    const envelope = encryptRecord(record, salt, key, 1);
    const sealed = sealPayload(
      Buffer.from(JSON.stringify(payload)),
      key,
      Buffer.from(envelope.nonce, 'base64'),
      aad(envelope)
    );
    expect(() =>
      decryptRecord(
        {
          ...envelope,
          ciphertext: sealed.ciphertext.toString('base64'),
          tag: sealed.tag.toString('base64'),
        },
        key,
        expected
      )
    ).toThrow();
  });

  test('rejects invalid encryption inputs before producing an envelope', () => {
    expect(() =>
      encryptRecord({ ...record, quantity: 0 }, salt, key, 1)
    ).toThrow(/quantity/);
    expect(() => encryptRecord(record, Field(2n ** 128n), key, 1)).toThrow(
      /salt/
    );
    expect(() => encryptRecord(record, salt, Buffer.alloc(31), 1)).toThrow(
      /key/
    );
    expect(() => encryptRecord(record, salt, key, 0)).toThrow(/keyVersion/);
    expect(encryptRecord(record, Field(0), key, 1).requestedRecordIdHash).toBe(
      hashIdentifier(record.recordId).toString()
    );
  });
});

describe('AES-only primitives', () => {
  test('matches the AES-256-GCM empty-plaintext published vector', () => {
    const sealed = sealPayload(
      Buffer.alloc(0),
      Buffer.alloc(32),
      Buffer.alloc(12),
      Buffer.alloc(0)
    );
    expect(sealed.ciphertext).toHaveLength(0);
    expect(sealed.tag.toString('hex')).toBe('530f8afbc74536b9a963b4f1c4cb738b');
    expect(
      openPayload(
        sealed.ciphertext,
        sealed.tag,
        Buffer.alloc(32),
        Buffer.alloc(12),
        Buffer.alloc(0)
      )
    ).toEqual(Buffer.alloc(0));
  });

  test('rejects bad primitive lengths/types and unauthenticated data', () => {
    const plaintext = Buffer.from('private payload');
    const nonce = randomBytes(12);
    const associated = Buffer.from('metadata');
    const sealed = sealPayload(plaintext, key, nonce, associated);
    expect(
      openPayload(sealed.ciphertext, sealed.tag, key, nonce, associated)
    ).toEqual(plaintext);
    expect(() =>
      sealPayload(plaintext, Buffer.alloc(16), nonce, associated)
    ).toThrow(/key/);
    expect(() =>
      sealPayload(plaintext, key, Buffer.alloc(11), associated)
    ).toThrow(/nonce/);
    expect(() =>
      sealPayload('text' as unknown as Buffer, key, nonce, associated)
    ).toThrow(/Buffer/);
    expect(() =>
      openPayload(sealed.ciphertext, Buffer.alloc(15), key, nonce, associated)
    ).toThrow(/tag/);
    expect(() =>
      openPayload(
        sealed.ciphertext,
        sealed.tag,
        key,
        Buffer.alloc(13),
        associated
      )
    ).toThrow(/nonce/);
    expect(() =>
      openPayload(
        sealed.ciphertext,
        sealed.tag,
        key,
        nonce,
        Buffer.from('changed')
      )
    ).toThrow(/authentic/i);
  });
});
