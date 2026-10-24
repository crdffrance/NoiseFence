import assert from 'node:assert/strict';
import test from 'node:test';
import {correctionRequest,correctionScopes} from '../app/correction.ts';
const base={mode:'general',category:'',domain:'',threat:'spam'};
const domains=[{domain:'one.example',class:'phishing'},{domain:'two.example',class:null}];
test('an explicit correction is required and never uses a detector opinion',()=>{
  assert.equal(correctionRequest(base,domains),null);
  for(const category of ['legitimate','publicity','spam']){
    const plan=correctionRequest({...base,category},null);
    assert.deepEqual(plan.body,{category});assert.equal(plan.endpoint,'feedback');
    assert.equal(plan.category,category);assert.match(plan.notice,/evaluation annotations remain unchanged/);
  }
  for(const category of ['ham','__proto__','constructor','undetermined'])assert.equal(correctionRequest({...base,category},domains),null);
});
test('a detailed correction uses one atomic domain write and maps phishing/scam to unwanted',()=>{
  for(const [category,threat,label] of [['legitimate','scam','legitimate'],['publicity','phishing','publicity'],['spam','phishing','phishing'],['spam','scam','scam'],['spam','spam','spam']]){
    const plan=correctionRequest({...base,mode:'detail',category,domain:'one.example',threat},domains);
    assert.equal(plan.endpoint,'adaptive-label');assert.deepEqual(plan.body,{domain:'one.example',class:label});assert.equal(plan.category,category);
  }
  for(const records of [null,[]])assert.equal(correctionRequest({...base,mode:'detail',category:'spam',domain:'one.example'},records),null);
  assert.equal(correctionRequest({...base,mode:'detail',category:'spam',domain:'other.example'},domains),null);
});
test('withdrawal targets an existing authorized detail and preserves general feedback',()=>{
  const plan=correctionRequest({...base,mode:'withdraw',domain:'one.example'},domains);
  assert.deepEqual(plan.body,{domain:'one.example',class:null});assert.equal(plan.category,undefined);
  assert.match(plan.notice,/general correction.*remain recorded/);
  for(const domain of ['','two.example','other.example'])assert.equal(correctionRequest({...base,mode:'withdraw',domain},domains),null);
});
test('operational, development and protected evaluation annotations have distinct scope',()=>{
  assert.match(correctionScopes.operational.detail,/Evaluation labels stay separate/);
  assert.match(correctionScopes.development.detail,/does not create operational feedback/);
  for(const purpose of ['regression','holdout'])assert.match(correctionScopes[purpose].detail,/excluded from training and sender trust/);
});
