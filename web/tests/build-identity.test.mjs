import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { consoleIdentity } from '../build-identity.mjs';
test('console source identity is deterministic and binds assets independently of version numbers',()=>{
  const root=mkdtempSync(join(tmpdir(),'nf-console-identity-'));
  try {
    for (const folder of ['app','components','lib','public','tests']) mkdirSync(join(root,folder));
    for (const file of ['index.html','package-lock.json','vite.config.ts','build-identity.mjs']) writeFileSync(join(root,file),file);
    writeFileSync(join(root,'package.json'),JSON.stringify({version:'1.2.3'}));
    const first=consoleIdentity(root);
    assert.deepEqual(consoleIdentity(root),first);
    writeFileSync(join(root,'tests/not-shipped.txt'),'test only');
    assert.deepEqual(consoleIdentity(root),first);
    writeFileSync(join(root,'public/favicon.svg'),'<svg/>');
    const changed=consoleIdentity(root);
    assert.equal(changed.version,first.version);
    assert.notEqual(changed.source_sha256,first.source_sha256);
    assert.match(changed.source_sha256,/^[a-f0-9]{64}$/);
  } finally {rmSync(root,{recursive:true,force:true});}
});
