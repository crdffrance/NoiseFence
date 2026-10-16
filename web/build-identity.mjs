import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join, relative } from 'node:path';

export function consoleIdentity(root) {
  const files = [];
  function collect(path) {
    for (const entry of readdirSync(path, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory()) collect(join(path, entry.name));
      else if (entry.isFile()) files.push(join(path, entry.name));
      else throw new Error('Console build inputs must be regular files');
    }
  }
  for (const directory of ['app', 'components', 'lib', 'public']) collect(join(root, directory));
  for (const file of ['index.html', 'package.json', 'package-lock.json', 'vite.config.ts', 'build-identity.mjs']) files.push(join(root, file));
  const hash = createHash('sha256');
  for (const file of files.sort((a, b) => a < b ? -1 : a > b ? 1 : 0)) {
    hash.update(relative(root, file).replaceAll('\\', '/') + '\0');
    hash.update(createHash('sha256').update(readFileSync(file)).digest());
  }
  return { schema: 'noisefence-console-1', version: JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version, source_sha256: hash.digest('hex') };
}
