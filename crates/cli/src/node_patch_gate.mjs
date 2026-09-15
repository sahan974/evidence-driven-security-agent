import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';

// Only the adapter's literal module/callable contract is supported.
const [source, mode] = process.argv.slice(1);
const modules = [...source.matchAll(/await import\(("(?:[^"\\]|\\.)*")\)/g)];
const calls = [...source.matchAll(/mod\[("(?:[^"\\]|\\.)*")\]\(payload\)/g)];
assert.equal(modules.length, 1, 'Unsupported replay module');
assert.equal(calls.length, 1, 'Unsupported replay callable');
const moduleName = JSON.parse(modules[0][1]);
const callable = JSON.parse(calls[0][1]);
assert(source.includes("const payload=control?'safe.txt':'../../etc/passwd';"), 'Unsupported replay payload');
const original = process.cwd();
const modulePath = path.resolve(original, moduleName);
assert(!path.relative(original, modulePath).startsWith('..'), 'Module outside repository');
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'edsa-node-patch-'));
try {
  const root = path.join(temporary, 'application');
  await fs.cp(original, root, { recursive: true, filter: p => path.basename(p) !== '.git' });
  try { await fs.access(path.join(root, 'node_modules')); } catch {
    try {
      await fs.access('/opt/edsa-dependencies/node_modules');
      await fs.symlink('/opt/edsa-dependencies/node_modules', path.join(root, 'node_modules'));
    } catch { /* Dependency-free modules need no prepared image. */ }
  }
  const sibling = path.join(temporary, 'application-sibling');
  await fs.mkdir(sibling);
  const outside = path.join(sibling, 'outside.txt');
  const marker = randomBytes(32).toString('hex');
  await fs.writeFile(outside, marker);
  await fs.mkdir(path.join(root, 'inside'), { recursive: true });
  await fs.symlink(outside, path.join(root, 'outside-link'));
  await fs.symlink(sibling, path.join(root, 'directory-link'));
  process.chdir(root);
  const mod = await import(pathToFileURL(path.join(root, path.relative(original, modulePath))));
  assert.equal(typeof mod[callable], 'function');
  // A repair that rejects all reads must fail, even with the expected error type.
  const safeName = `edsa-safe-${randomBytes(12).toString('hex')}.txt`;
  await fs.writeFile(safeName, marker);
  assert.equal(String(await mod[callable](safeName)), marker, 'Safe read changed');
  const candidates = [
    '../application-sibling/outside.txt', outside,
    './../application-sibling/outside.txt', 'inside/../../application-sibling/outside.txt',
    '../application-sibling/./outside.txt', '../application-sibling//outside.txt',
    'outside-link', 'directory-link/outside.txt',
  ];
  const index = Number(mode);
  assert(mode === 'proof' || (Number.isInteger(index) && index >= 0 && index < 8));
  const candidate = mode === 'proof' ? '../../etc/passwd' : candidates[index];
  if (mode !== 'proof') assert.equal(await fs.realpath(candidate), outside);
  let blocked = false;
  try {
    await mod[callable](candidate);
  } catch (error) {
    // Filesystem failures and programming errors cannot establish rejection.
    if (error?.constructor === Error && (!error.code || error.code === 'EACCES')) {
      blocked = true;
    } else {
      throw error;
    }
  }
  assert(blocked, 'Candidate returned without rejecting the path');
  console.log(JSON.stringify({ mode, candidate, blocked }));
  console.log(mode === 'proof' ? 'EDSA_PATCH_BLOCKED' : 'EDSA_VARIANT_BLOCKED');
} finally {
  process.chdir(original);
  await fs.rm(temporary, { recursive: true, force: true });
}
