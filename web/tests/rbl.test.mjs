import assert from 'node:assert/strict';
import test from 'node:test';
import {rblStatus,rblIncident} from '../app/rbl-types.ts';
test('RBL absence, policy and provider failure remain distinguishable',()=>{
  assert.equal(rblStatus('not_listed'),'IP non listée');
  assert.equal(rblStatus('policy'),'Liste de politique · sans vote de blocage');
  assert.notEqual(rblStatus('unavailable'),rblStatus('not_listed'));
  assert.equal(rblIncident('invalid_answer'),'Code de réponse non reconnu ou erreur du fournisseur');
  assert.equal(rblStatus('<script>private</script>'),'État inconnu');
  assert.equal(rblIncident('private query key'),'');
});
