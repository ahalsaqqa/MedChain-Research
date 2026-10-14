import type { MedicineRecord } from './records.js';

export const SYNTHETIC_GENERATOR_VERSION = 'medchain-synthetic-v1';

/** Deterministic synthetic contents only. This generator never supplies secrets. */
export function syntheticRecords(size: number, seed: number): MedicineRecord[] {
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('size must be a nonnegative safe integer');
  if (!Number.isSafeInteger(seed)) throw new Error('seed must be a safe integer');
  let state = seed >>> 0;
  const next = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
  return Array.from({ length: size }, (_, index) => {
    const occurredAt = 1700000000 + (next() % 31536000);
    return {
      recordId: `synthetic-${seed}-${index}`,
      medicineId: `medicine-${next() % 200}`,
      batchId: `batch-${next() % 500}`,
      manufacturerId: `manufacturer-${next() % 20}`,
      distributorId: `distributor-${next() % 40}`,
      pharmacyId: `pharmacy-${next() % 100}`,
      quantity: 1 + (next() % 1000),
      occurredAt,
      expiresAt: occurredAt + 31536000 + (next() % 31536000),
    };
  });
}
