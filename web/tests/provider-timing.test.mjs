import assert from 'node:assert/strict';
import test from 'node:test';
import {timingRows} from '../app/provider-timing.ts';
test('timings distinguish network and queue cancellation without echoing private fields',()=>{
  const rows=timingRows({budget_ms:1200,deadline_exceeded:true,
    phase_ms:{cache:0,capacity:100,response_headers:1100,response_body:NaN,'PRIVATE URL':50},
    cancelled:{response_headers:1}});
  assert.equal(rows.length,3);
  assert.equal(rows[0].ms,0);
  assert.equal(rows[2].cancelled,1);
  assert.equal(rows[1].cancelled,0);
  assert.ok(!JSON.stringify(rows).includes('PRIVATE'));
});
