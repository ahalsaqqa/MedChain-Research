import { createHash } from 'node:crypto';
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { ContentStore } from '../src/storage.js';
import { Keyring } from '../src/keyring.js';
import { encryptRecord, serializeEnvelope } from '../src/encryption.js';
import { Field } from 'o1js';

const testRoot = resolve('work/task-3-tests');
let directory: string;
beforeEach(async () => {
  await mkdir(testRoot, { recursive: true });
  directory = await mkdtemp(join(testRoot, 'case-'));
});
afterEach(async () => {
  const target = resolve(directory);
  if (!target.startsWith(testRoot + sep))
    throw new Error('unsafe test cleanup');
  await rm(target, { recursive: true, force: true });
});

test('stores exact bytes by SHA-256 and retrieves verified bytes', async () => {
  const store = new ContentStore(directory);
  const bytes = Buffer.from('abc');
  const digest = await store.put(bytes);
  expect(digest).toBe(
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
  expect(await readFile(join(directory, digest))).toEqual(bytes);
  expect(await store.get(digest)).toEqual(bytes);
  expect(await store.put(bytes)).toBe(digest);
});

test('distinguishes absent content, digest mismatch and malformed identifiers', async () => {
  const store = new ContentStore(directory);
  await expect(store.get('0'.repeat(64))).rejects.toThrow(/missing content/i);
  const digest = await store.put(Buffer.from('content'));
  await writeFile(join(directory, digest), 'tampered');
  await expect(store.get(digest)).rejects.toThrow(/digest mismatch/i);
  for (const invalid of [
    '../outside',
    'A'.repeat(64),
    '',
    '0'.repeat(63),
    null,
    {},
    [],
  ]) {
    await expect(store.get(invalid as string)).rejects.toThrow(
      /invalid digest/i
    );
  }
  await expect(store.put('text' as unknown as Buffer)).rejects.toThrow(
    /Buffer/
  );
});

test('refuses an existing corrupted content object instead of reporting write success', async () => {
  const bytes = Buffer.from('correct');
  const digest = createHash('sha256').update(bytes).digest('hex');
  await writeFile(join(directory, digest), 'incorrect');
  await expect(new ContentStore(directory).put(bytes)).rejects.toThrow(
    /digest mismatch/i
  );
});

test('rejects non-file content objects', async () => {
  const digest = 'a'.repeat(64);
  await mkdir(join(directory, digest));
  await expect(new ContentStore(directory).get(digest)).rejects.toThrow(
    /regular file/i
  );
  await expect(
    new ContentStore(directory).put(Buffer.alloc(0))
  ).resolves.toMatch(/^[a-f0-9]{64}$/);
});

test('failed eleventh storage write leaves committed version/count unchanged; checked retry commits', async () => {
  const ring = new Keyring();
  const store = new ContentStore(join(directory, 'objects'));
  const record = {
    recordId: 'r',
    medicineId: 'm',
    batchId: 'b',
    manufacturerId: 'f',
    distributorId: 'd',
    pharmacyId: 'p',
    quantity: 1,
    occurredAt: 0,
    expiresAt: 1,
  };
  for (let i = 0; i < 10; i++) {
    const prepared = ring.prepare();
    await store.put(
      serializeEnvelope(
        encryptRecord(record, Field(1), prepared.key, prepared.version)
      )
    );
    ring.commitWrite(prepared.version);
  }
  const pending = ring.prepare();
  const failedEnvelope = encryptRecord(
    record,
    Field(1),
    pending.key,
    pending.version
  );
  await writeFile(join(directory, 'blocked'), 'not a directory');
  await expect(
    new ContentStore(join(directory, 'blocked')).put(
      serializeEnvelope(failedEnvelope)
    )
  ).rejects.toThrow();
  expect(ring.status()).toEqual({ activeVersion: 1, successfulWrites: 10 });
  const retry = ring.prepare();
  const retriedEnvelope = encryptRecord(
    record,
    Field(1),
    retry.key,
    retry.version
  );
  expect(retriedEnvelope.nonce).not.toBe(failedEnvelope.nonce);
  await store.put(serializeEnvelope(retriedEnvelope));
  ring.commitWrite(retry.version);
  expect(ring.status()).toEqual({ activeVersion: 2, successfulWrites: 1 });
});

test('serializes concurrent writes and recovers after a failed write', async () => {
  const store = new ContentStore(directory);
  const bad = Buffer.from('bad');
  await writeFile(
    join(directory, createHash('sha256').update(bad).digest('hex')),
    'corrupt'
  );
  const results = await Promise.allSettled([
    store.put(bad),
    store.put(Buffer.from('good')),
    store.put(Buffer.from('good')),
  ]);
  expect(results[0].status).toBe('rejected');
  expect(results[1].status).toBe('fulfilled');
  expect(results[2]).toEqual(results[1]);
});

// Windows can prohibit symlinks without Developer Mode/elevation: report explicitly.
const symlinkAllowed = (() => {
  mkdirSync(testRoot, { recursive: true });
  const probe = mkdtempSync(join(testRoot, 'symlink-probe-'));
  try {
    writeFileSync(join(probe, 'target'), 'x');
    symlinkSync(join(probe, 'target'), join(probe, 'link'), 'file');
    return true;
  } catch (error) {
    if (
      !['EPERM', 'EACCES', 'ENOSYS'].includes(
        (error as NodeJS.ErrnoException).code ?? ''
      )
    )
      throw error;
    return false;
  } finally {
    if (!resolve(probe).startsWith(testRoot + sep))
      throw new Error('unsafe cleanup');
    rmSync(probe, { recursive: true, force: true });
  }
})();
(symlinkAllowed ? test : test.skip)(
  'rejects stored hex-name symlinks without reading their targets (requires platform symlink support)',
  async () => {
    const bytes = Buffer.from('outside');
    const digest = createHash('sha256').update(bytes).digest('hex');
    const objects = join(directory, 'objects');
    await mkdir(objects);
    await writeFile(join(directory, 'outside'), bytes);
    await symlink(join(directory, 'outside'), join(objects, digest), 'file');
    const store = new ContentStore(objects);
    await expect(store.get(digest)).rejects.toThrow(/regular file|symlink/i);
    await expect(store.put(bytes)).rejects.toThrow(/regular file|symlink/i);
  }
);

const directoryLinkType = (() => {
  mkdirSync(testRoot, { recursive: true });
  const probe = mkdtempSync(join(testRoot, 'directory-link-probe-'));
  try {
    mkdirSync(join(probe, 'target'));
    const types: Array<'dir' | 'junction'> =
      process.platform === 'win32' ? ['dir', 'junction'] : ['dir'];
    for (const type of types) {
      try {
        symlinkSync(join(probe, 'target'), join(probe, `${type}-link`), type);
        return type;
      } catch (error) {
        if (
          !['EPERM', 'EACCES', 'ENOSYS'].includes(
            (error as NodeJS.ErrnoException).code ?? ''
          )
        )
          throw error;
      }
    }
    return undefined;
  } finally {
    if (!resolve(probe).startsWith(testRoot + sep))
      throw new Error('unsafe cleanup');
    rmSync(probe, { recursive: true, force: true });
  }
})();

(directoryLinkType ? test : test.skip).each(['put', 'get'] as const)(
  '%s rejects a linked ancestor before creating missing directories in its target (requires directory-link support)',
  async (operation) => {
    const owned = join(directory, 'owned');
    const outside = join(directory, 'outside');
    await mkdir(owned);
    await mkdir(outside);
    await symlink(outside, join(owned, 'link'), directoryLinkType!);
    const store = new ContentStore(join(owned, 'link', 'new-store'));
    await expect(
      operation === 'put'
        ? store.put(Buffer.from('content'))
        : store.get('0'.repeat(64))
    ).rejects.toThrow(/symlink/i);
    await expect(lstat(join(outside, 'new-store'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  }
);
