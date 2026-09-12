import assert from 'node:assert/strict';
import test from 'node:test';
import {rate,stateLabel} from '../app/reliability-types.ts';
test('missing or invalid quality estimates never display zero errors',()=>{
  assert.equal(rate(null),'Non mesurable');
  assert.equal(rate({total:0,events:0,value:0,lower:0,upper:1}),'Non mesurable');
  assert.equal(rate({total:1,events:0,value:NaN,lower:0,upper:1}),'Non mesurable');
  assert.match(rate({total:10,events:0,value:0,lower:0,upper:.2775}),/27,75/);
});
test('availability is explicit and unknown provider content is never echoed',()=>{
  assert.equal(stateLabel('quota'),'Quota atteint');assert.equal(stateLabel('unavailable'),'Indisponible');
  assert.equal(stateLabel('<script>private</script>'),'État indéterminé');
  assert.notEqual(stateLabel('clean'),stateLabel('disabled'));
});

test('coverage and missed-message diagnostics use fixed labels',async()=>{
  const {detailLabel,diagnosticLabel}=await import('../app/reliability-types.ts');
  assert.equal(detailLabel('client_script'),'Destination dépendante de JavaScript');
  assert.equal(detailLabel('forbidden_address'),'Adresse réseau interdite');
  assert.equal(diagnosticLabel('decision_disagreement'),'Désaccord entre les avis');
  assert.equal(detailLabel('PRIVATE URL'),'Limite non reconnue');
  assert.equal(diagnosticLabel('<script>private</script>'),'Contexte non reconnu');
});
