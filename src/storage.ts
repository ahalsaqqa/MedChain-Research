import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath } from 'node:fs/promises';
import { dirname, join, relative, resolve, isAbsolute } from 'node:path';

const digestOf = (bytes: Buffer) =>
  createHash('sha256').update(bytes).digest('hex');

async function requireRealDirectory(directory: string): Promise<void> {
  const info = await lstat(directory);
  if (
    !info.isDirectory() ||
    info.isSymbolicLink() ||
    relative(directory, await realpath(directory)) !== ''
  )
    throw new Error(
      'content directory must be a real directory without symlinks'
    );
}

/** Exact-byte SHA-256 content addressing in an owned local directory; no crash-durability claim. */
export class ContentStore {
  #directory: string;
  #writes: Promise<unknown> = Promise.resolve();

  constructor(directory: string) {
    if (typeof directory !== 'string' || directory.length === 0)
      throw new Error('content directory must be a nonempty path');
    this.#directory = resolve(directory);
  }

  async #path(digest: string): Promise<string> {
    if (
      typeof digest !== 'string' ||
      digest.length !== 64 ||
      !/^[a-f0-9]{64}$/.test(digest)
    )
      throw new Error('invalid digest');
    const path = join(this.#directory, digest);
    const child = relative(this.#directory, path);
    if (child.startsWith('..') || isAbsolute(child))
      throw new Error('digest path escapes content directory');
    // Check the closest existing ancestor before mkdir can follow a link and
    // create missing descendants outside the configured tree.
    let ancestor = this.#directory;
    for (;;) {
      try {
        await requireRealDirectory(ancestor);
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const parent = dirname(ancestor);
        if (parent === ancestor) throw error;
        ancestor = parent;
      }
    }
    await mkdir(this.#directory, { recursive: true });
    await requireRealDirectory(this.#directory);
    return path;
  }

  put(bytes: Buffer): Promise<string> {
    if (!Buffer.isBuffer(bytes))
      return Promise.reject(new Error('content must be a Buffer'));
    // Own the queued bytes so caller mutation cannot change the intended content ID.
    const owned = Buffer.from(bytes);
    const operation = this.#writes.then(async () => {
      const digest = digestOf(owned);
      const path = await this.#path(digest);
      try {
        const file = await open(path, 'wx', 0o600);
        try {
          await file.writeFile(owned);
        } finally {
          await file.close();
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      await this.get(digest);
      return digest;
    });
    this.#writes = operation.catch(() => undefined);
    return operation;
  }

  async get(digest: string): Promise<Buffer> {
    const path = await this.#path(digest);
    try {
      const before = await lstat(path);
      if (!before.isFile() || before.isSymbolicLink())
        throw new Error(
          'content object must be a regular file, never a symlink'
        );
      const file = await open(
        path,
        constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
      );
      try {
        const after = await file.stat();
        if (
          !after.isFile() ||
          before.dev !== after.dev ||
          before.ino !== after.ino
        )
          throw new Error('content object must remain the same regular file');
        const bytes = await file.readFile();
        if (digestOf(bytes) !== digest)
          throw new Error('content digest mismatch');
        return bytes;
      } finally {
        await file.close();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT')
        throw new Error('missing content object');
      throw error;
    }
  }
}
