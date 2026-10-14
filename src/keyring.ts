import { randomBytes } from 'node:crypto';

/** Process-local key custody. Commit only after ContentStore.put has checked persistence. */
export class Keyring {
  #keys = new Map<number, Buffer>([[1, randomBytes(32)]]);
  #activeVersion = 1;
  #successfulWrites = 0;
  #pendingVersion: number | undefined;

  prepare(): { version: number; key: Buffer } {
    if (this.#successfulWrites === 10 && this.#pendingVersion === undefined) {
      this.#pendingVersion = this.#activeVersion + 1;
      this.#keys.set(this.#pendingVersion, randomBytes(32));
    }
    const version = this.#pendingVersion ?? this.#activeVersion;
    return { version, key: this.get(version) };
  }

  commitWrite(version: number): void {
    const expected =
      this.#successfulWrites === 10
        ? this.#pendingVersion
        : this.#activeVersion;
    if (!Number.isSafeInteger(version) || version !== expected)
      throw new Error('unexpected key version for write commit');
    if (this.#pendingVersion !== undefined) {
      this.#activeVersion = this.#pendingVersion;
      this.#pendingVersion = undefined;
      this.#successfulWrites = 0;
    }
    this.#successfulWrites++;
  }

  get(version: number): Buffer {
    const key = this.#keys.get(version);
    if (!Number.isSafeInteger(version) || !key)
      throw new Error('unknown key version');
    return Buffer.from(key);
  }

  status(): { activeVersion: number; successfulWrites: number } {
    return {
      activeVersion: this.#activeVersion,
      successfulWrites: this.#successfulWrites,
    };
  }
}
