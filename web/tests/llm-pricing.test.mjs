import assert from 'node:assert/strict';
import test from 'node:test';
import { llmPricingStatus } from '../app/llm-pricing.ts';
const checked=1800000000;
test('pricing expires at the same strict boundary as the server',()=>{
  assert.equal(llmPricingStatus(checked,checked+30*86400).state,'expiring');
  assert.equal(llmPricingStatus(checked,checked+30*86400+1).state,'expired');
  assert.equal(llmPricingStatus(checked,checked-1).state,'expired');
});
test('warning precedes the cutoff and never implies general provider readiness',()=>{
  assert.equal(llmPricingStatus(checked,checked+23*86400).state,'expiring');
  const fresh=llmPricingStatus(checked,checked);
  assert.equal(fresh.state,'current');
  assert.match(fresh.message,/other availability limits/);
  for(const value of [null,undefined,NaN,Infinity,'1800000000'])
    assert.equal(llmPricingStatus(value,checked).state,'unknown');
});
