import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import {scorePresentation, classification} from '../app/presentation.ts';
import {coveragePresentation} from '../app/assessment.ts';
const cases=JSON.parse(readFileSync(new URL('../../tests/fixtures/assessment.json',import.meta.url),'utf8'));

test('the console consumes the same versioned assessment cases as Rust and SMTP headers',()=>{
  for(const c of cases){
    const input=c.scan,e=c.expected;
    const assessment={version:1, score:{value:e.value,kind:e.kind,source:e.source,model:e.source==='decision'?input.decision?.model:input.model,scale:100,raw:input.score,decision:input.decision?.score??null},category:e.category,classification_source:e.classification_source,complete:input.complete,incomplete_reasons:input.complete?[]:(input.reasons??[]).map(r=>r.id),content_threshold:input.analysis_policy?.threshold??null,mode:input.analysis_policy?.mode??null,policy_version:input.analysis_policy?.version??null,action:null,subject_tag:'none'};
    const mail={...input,category:e.category,assessment};
    assert.equal(scorePresentation(mail).value,e.value,c.name);
    assert.equal(scorePresentation(mail).kind,e.kind,c.name);
    assert.equal(classification(mail).label,input.decision?.source==='antivirus'?'Malware':{spam:'Spam',publicity:'Marketing',legitimate:'Legitimate',undetermined:'Historical decision unavailable'}[e.category],c.name);
    assert.equal(coveragePresentation(mail).complete,input.complete,c.name);
    // A UI-local raw score or settings change cannot reinterpret the server assessment.
    assert.equal(scorePresentation({...mail,score:42}).value,e.value,c.name);
    assert.equal(classification(mail,50).label,classification(mail,100).label,c.name);
  }
});

test('classification and coverage are visible independently, including recorded custom rules',()=>{
  const mail={score:99,complete:false,tagged:false,pub_tagged:false,category:'spam',delivery_classification:'spam',decision:{source:'legacy',outcome:'undetermined',score:null}};
  assert.equal(classification(mail).label,'Spam');
  assert.equal(scorePresentation(mail).kind,'partial');
  assert.equal(coveragePresentation(mail).label,'Partial analysis');
});


test('optional gaps remain visible without claiming a partial core scan or changing its score',()=>{
  const mail={complete:true,assessment:{complete:true,incomplete_reasons:[],supplementary_gaps:['virustotal','url_resolution']}};
  const shown=coveragePresentation(mail);
  assert.equal(shown.complete,true);
  assert.equal(shown.hasGaps,true);
  assert.match(shown.label,/limited checks/);
  assert.match(shown.detail,/VirusTotal reputation, URL destinations/);
  assert.doesNotMatch(shown.detail,/Configured checks completed/);
});
