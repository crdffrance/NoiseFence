import assert from 'node:assert/strict';
import test from 'node:test';
import { candidateLabel, mailKinds } from '../app/quality-types.ts';

test('unknown candidate states never echo provider content or imply activation',()=>{
  assert.equal(candidateLabel('<script>private token</script>'),'État indisponible');
  assert.match(candidateLabel('complete'),/observation/);
  assert.match(candidateLabel('not_configured'),/attente/);
  assert.match(candidateLabel('incompatible'),/incompatible/);
});
test('mail kind vocabulary separates commercial and useful transactional mail',()=>{
  assert.equal(Object.keys(mailKinds).length,6);
  assert.notEqual(mailKinds.transactional,mailKinds.promotion);
  assert.notEqual(mailKinds.notification,mailKinds.newsletter);
});

test('missing kind model never invents a conversation or a safe classification',async()=>{
  const {mailKindLabel}=await import('../app/quality-types.ts');
  assert.equal(mailKindLabel('unavailable'),'Type indéterminé');
  assert.equal(mailKindLabel('<script>private</script>'),'Type indéterminé');
  assert.equal(mailKindLabel('newsletter'),'Newsletter');
});
