import assert from 'node:assert/strict';
import test from 'node:test';
import {rblStatus,rblIncident} from '../app/rbl-types.ts';
test('RBL absence, policy and provider failure remain distinguishable',()=>{
  assert.equal(rblStatus('not_listed'),"IP not listed");
  assert.equal(rblStatus('policy'),"Policy list · without blocking vote");
  assert.notEqual(rblStatus('unavailable'),rblStatus('not_listed'));
  assert.equal(rblIncident('invalid_answer'),"Unrecognized response code or provider error");
  assert.equal(rblStatus('<script>private</script>'),"Unknown State");
  assert.equal(rblIncident('private query key'),'');
});
