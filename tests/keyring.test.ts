import { Field } from 'o1js';
import { Keyring } from '../src/keyring.js';
import { encryptRecord, decryptRecord } from '../src/encryption.js';
import { recordCommitment } from '../src/records.js';

describe('transactional operation-count rotation', () => {
  test('keeps version 2 pending until commit and retains earlier decryption', () => {
    const ring = new Keyring();
    const record = {
      recordId: 'old',
      medicineId: 'm',
      batchId: 'b',
      manufacturerId: 'f',
      distributorId: 'd',
      pharmacyId: 'p',
      quantity: 1,
      occurredAt: 0,
      expiresAt: 1,
    };
    const first = ring.prepare();
    const envelope = encryptRecord(record, Field(1), first.key, first.version);
    for (let count = 1; count <= 10; count++) {
      const prepared = ring.prepare();
      expect(prepared.version).toBe(1);
      ring.commitWrite(prepared.version);
      expect(ring.status()).toEqual({
        activeVersion: 1,
        successfulWrites: count,
      });
    }
    const pending = ring.prepare();
    expect(pending.version).toBe(2);
    expect(pending.key).not.toEqual(first.key);
    // No persistence success has occurred, so the caller has no commit to make.
    expect(ring.status()).toEqual({ activeVersion: 1, successfulWrites: 10 });
    const retry = ring.prepare();
    expect(retry.key).toEqual(pending.key);
    ring.commitWrite(retry.version);
    expect(ring.status()).toEqual({ activeVersion: 2, successfulWrites: 1 });
    expect(
      decryptRecord(envelope, ring.get(1), {
        id: 'old',
        commitment: recordCommitment(record, Field(1)),
      }).record
    ).toEqual(record);
    expect(ring.prepare().version).toBe(2);
  });

  test('preparation never counts a write and key copies cannot mutate retained keys', () => {
    const ring = new Keyring();
    const first = ring.prepare();
    const retained = Buffer.from(first.key);
    first.key.fill(0);
    ring.get(1).fill(0);
    expect(ring.prepare().key).toEqual(retained);
    expect(ring.status()).toEqual({ activeVersion: 1, successfulWrites: 0 });
    expect(JSON.stringify(ring)).toBe('{}');
    expect(Object.keys(ring)).toEqual([]);
    expect(Object.keys(ring.status())).toEqual([
      'activeVersion',
      'successfulWrites',
    ]);
  });

  test('rejects unknown, stale, unprepared and malformed versions without state change', () => {
    const ring = new Keyring();
    for (const invalid of [0, -1, 1.5, NaN, 2]) {
      expect(() => ring.commitWrite(invalid)).toThrow(/version/);
      expect(() => ring.get(invalid)).toThrow(/version/);
    }
    for (let i = 0; i < 10; i++) ring.commitWrite(ring.prepare().version);
    expect(() => ring.commitWrite(1)).toThrow(/version/);
    expect(() => ring.commitWrite(2)).toThrow(/version/);
    expect(ring.status()).toEqual({ activeVersion: 1, successfulWrites: 10 });
    ring.commitWrite(ring.prepare().version);
    expect(() => ring.commitWrite(1)).toThrow(/version/);
    expect(ring.status()).toEqual({ activeVersion: 2, successfulWrites: 1 });
  });
});
