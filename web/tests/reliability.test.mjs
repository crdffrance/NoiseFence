import assert from 'node:assert/strict';
import test from 'node:test';
import {rate,stateLabel} from '../app/reliability-types.ts';
test('missing or invalid quality estimates never display zero errors',()=>{
  assert.equal(rate(null),"Not measurable");
  assert.equal(rate({total:0,events:0,value:0,lower:0,upper:1}),"Not measurable");
  assert.equal(rate({total:1,events:0,value:NaN,lower:0,upper:1}),"Not measurable");
  assert.match(rate({total:10,events:0,value:0,lower:0,upper:.2775}),/27\.75/);
});
test('availability is explicit and unknown provider content is never echoed',()=>{
  assert.equal(stateLabel('quota'),"Quota reached");assert.equal(stateLabel('unavailable'),"Unavailable");
  assert.equal(stateLabel('<script>private</script>'),"Undetermined State");
  assert.notEqual(stateLabel('clean'),stateLabel('disabled'));
});

test('coverage and missed-message diagnostics use fixed labels',async()=>{
  const {detailLabel,diagnosticLabel}=await import('../app/reliability-types.ts');
  assert.equal(detailLabel('client_script'),"JavaScript dependent destination");
  assert.equal(detailLabel('forbidden_address'),"Prohibited network address");
  assert.equal(diagnosticLabel('decision_disagreement'),"Disagreement between opinions");
  assert.equal(detailLabel('PRIVATE URL'),"Limit not recognized");
  assert.equal(diagnosticLabel('<script>private</script>'),"Unrecognized context");
});
