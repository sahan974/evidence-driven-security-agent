import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'edsa-node-tests-'));
try {
  await fs.cp(process.cwd(), temporary, { recursive: true, filter: p => path.basename(p) !== '.git' });
  const manifest = JSON.parse(await fs.readFile(path.join(temporary, 'package.json'), 'utf8'));
  if (!manifest.scripts?.test) throw new Error('Repository has no test script');
  const localDependencies = path.join(temporary, 'node_modules');
  try { await fs.access(localDependencies); } catch {
    if (Object.keys({ ...manifest.dependencies, ...manifest.devDependencies }).length) {
      await fs.access('/opt/edsa-dependencies/node_modules');
      await fs.symlink('/opt/edsa-dependencies/node_modules', localDependencies);
    }
  }
  const result = spawnSync('npm', ['test'], {
    cwd: temporary, stdio: 'inherit', env: { ...process.env, CI: 'true' },
  });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  await fs.rm(temporary, { recursive: true, force: true });
}
