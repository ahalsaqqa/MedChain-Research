// Copy only public benchmark outputs; raw diagnostics and run scratch never leave work/.
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
const root = resolve('.');
const out = join(root, 'work/cloud-evidence');
const inventory = [], rejected = [], statuses = {};
const sha = (v) => createHash('sha256').update(v).digest('hex');
const publicName = /^(metadata\.json|events\.jsonl|observations\.(jsonl|json|csv)|summaries\.(json|csv)|membership-proof-N(100|500|1000)\.json|membership-verification-key\.json|registry-verification-key\.json)$/;
const sensitive = /(?:[A-Z]:[\\/](?:Users|Program Files)[\\/]|\/(?:home|Users)\/[^/\s]+\/|-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/;
function regular(path) { const s = lstatSync(path); if (!s.isFile() || s.isSymbolicLink()) throw Error('nonregular'); }
function check(value) {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (/^(privateKey|secretKey|administratorKey|salt|salts|plaintext|witness|witnesses|ciphertext|nonce|PINATA_JWT)$/i.test(key)) throw Error('private-field');
    check(child);
  }
}
function save(name, original, bytes, transformation) {
  if (sensitive.test(bytes.toString('utf8'))) throw Error('sensitive-content');
  const target = join(out, name); mkdirSync(resolve(target, '..'), { recursive: true });
  writeFileSync(target, bytes, { flag: 'wx' });
  inventory.push({ path: name, bytes: bytes.length, sha256: sha(bytes), originalSHA256: sha(original), transformation });
}
mkdirSync(out, { recursive: true });
for (const stage of ['install', 'build', 'functional', 'benchmark']) {
  try {
    const status = join(root, `work/cloud-logs/${stage}.exit.txt`);
    statuses[stage] = existsSync(status) ? readFileSync(status, 'utf8').trim() : 'not-completed-or-not-started';
    if (!/^(\d{1,3}|not-completed-or-not-started)$/.test(statuses[stage])) throw Error('invalid-status');
    const path = join(root, `work/cloud-logs/${stage}.raw.txt`);
    const original = existsSync(path) ? (regular(path), readFileSync(path)) : Buffer.alloc(0);
    let text = original.toString('utf8').replace(/\x1b\[[0-9;]*m/g, '');
    for (const p of [root, process.env.GITHUB_WORKSPACE, process.env.RUNNER_TEMP, process.env.HOME].filter(Boolean)) text = text.replaceAll(p, '<runner-path>');
    // Exclude arbitrary failure payloads, source excerpts and stacks. Retain readable command/test summaries.
    text = text.split(/\r?\n/).filter((line) => /^(>|PASS |FAIL |Test Suites:|Tests:|Snapshots:|Time:|Ran all test suites|\s*[✓✕○] |added \d+ packages|\d+ vulnerabilities?)/.test(line)).join('\n');
    save(`logs/${stage}.txt`, original, Buffer.from(`Stage: ${stage}\nExit: ${statuses[stage]}\nPolicy: command/test summary only; private failure details omitted.\n${text}\n`), 'allowlisted log lines; runner paths replaced');
  } catch { rejected.push(`logs/${stage}`); }
}
const parent = join(root, 'work/benchmark-full');
if (existsSync(parent)) for (const entry of readdirSync(parent, { withFileTypes: true })) {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(entry.name) || !entry.isDirectory() || entry.isSymbolicLink()) continue;
  for (const name of readdirSync(join(parent, entry.name))) {
    if (!publicName.test(name)) continue;
    try {
      const path = join(parent, entry.name, name); regular(path);
      const bytes = readFileSync(path), text = bytes.toString('utf8');
      if (name.endsWith('.json')) check(JSON.parse(text));
      if (name.endsWith('.jsonl')) text.split('\n').filter(Boolean).forEach((line) => check(JSON.parse(line)));
      save(`runs/${entry.name}/${name}`, bytes, bytes, 'none; byte-identical allowlisted public evidence');
    } catch { rejected.push(`runs/${entry.name}/${name}`); }
  }
}
writeFileSync(join(out, 'manifest.json'), JSON.stringify({ schemaVersion: 1, createdAt: new Date().toISOString(), github: { runId: process.env.GITHUB_RUN_ID ?? null, attempt: process.env.GITHUB_RUN_ATTEMPT ?? null, sourceSHA: process.env.GITHUB_SHA ?? null }, statuses, inventory, rejected, policy: 'Only listed public evidence and sanitized log derivatives. Missing finalization is not success.' }, null, 2) + '\n', { flag: 'wx' });
console.log(`Collected ${inventory.length} sanitized files; rejected ${rejected.length}.`);
if (rejected.length) process.exitCode = 1;
