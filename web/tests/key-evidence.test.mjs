import assert from 'node:assert/strict';
import test from 'node:test';
import { keyEvidence } from '../app/key-evidence.ts';
const reasons = [
  {id:'model_contribution',weight:99,detail:'Summary only'},
  {id:'excluded',weight:80,detail:'Excluded detector'},
  {id:'auth',weight:-3,detail:'Observed authentication'},
  {id:'auth',weight:-3,detail:'Repeated evidence'},
  {id:'links',weight:2,detail:'Observed links'},
];
const scoring = {lexical:4,semantic:0.5,contributions:[{id:'excluded',retained:0},{id:'auth',retained:-3},{id:'links',retained:2}]};
test('the summary retains negative evidence and never duplicates model summaries or proposed votes',()=>{
  assert.deepEqual(keyEvidence('legacy',reasons,scoring).map(x=>[x.id,x.value]),[['lexical',4],['auth',-3],['links',2]]);
  assert.deepEqual(keyEvidence('legacy',reasons,null),[]);
  assert.deepEqual(keyEvidence('antivirus',reasons,scoring),[]);
  assert.deepEqual(keyEvidence('rspamd',reasons,scoring),[]);
});
test('fusion is ranked in its own ledger and never borrows the legacy model score',()=>{
  const fusion={families:{content:{raw:100,retained:0.2},authentication:{raw:-3,retained:-1},invalid:{raw:3,retained:NaN}}};
  assert.deepEqual(keyEvidence('fusion',reasons,scoring,fusion).map(x=>[x.id,x.value]),[['authentication',-1],['content',0.2]]);
  assert.deepEqual(keyEvidence('fusion',reasons,scoring),[]);
});
