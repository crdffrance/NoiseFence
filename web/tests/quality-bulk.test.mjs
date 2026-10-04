import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';
async function moduleURL(file,bindings={}) {
  const source=await readFile(new URL(file,import.meta.url),'utf8');
  const js=ts.transpileModule(source,{compilerOptions:{jsx:ts.JsxEmit.ReactJSX,module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
    .replace(/from (["'])([^"']+)\1/g,(_,q,name)=>`from ${JSON.stringify(bindings[name]??import.meta.resolve(name))}`);
  return `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`;
}
const utils=await moduleURL('../lib/utils.ts');
const button=await moduleURL('../components/ui/button.tsx',{'@/lib/utils':utils});
const input=await moduleURL('../components/ui/input.tsx',{'@/lib/utils':utils});
const {AnnotationList}=await import(await moduleURL('../app/quality-annotations.tsx',{
  '@/components/ui/button':button,'@/components/ui/input':input,
  './client':new URL('../app/client.ts',import.meta.url).href,
  './quality-types':new URL('../app/quality-types.ts',import.meta.url).href,
}));
test('bulk annotations start without inferred labels or selection and preserve existing annotations by default',()=>{
  const html=renderToStaticMarkup(createElement(AnnotationList,{members:[{id:'one',created:1,sender:'sender@example.test',subject:'<script>unsafe</script>',risk:null,kind:null,joint_observations:true}],user:{username:'alice',csrf:'fixture',admin:false,addresses:[]},batch:'sample',onSaved:()=>{},onBusy:()=>{}}));
  assert.match(html,/Apply to 0 selected/);
  assert.match(html,/Choose a human verdict/);
  assert.match(html,/Keep existing type/);
  assert.match(html,/PUB · Newsletter/);
  assert.match(html,/Replace my existing annotations/);
  assert.doesNotMatch(html,/checked=""/);
  assert.doesNotMatch(html,/<script>unsafe/);
  assert.match(html,/&lt;script&gt;unsafe/);
  assert.match(html,/newsletter may be wanted or unwanted/);
});

const {SoftwareStatus} = await import(await moduleURL('../app/software.tsx', {
  '@/components/ui/button': button,
  './client': new URL('../app/client.ts', import.meta.url).href,
}));
test('software identity is not fabricated and update checks are opt-in for administrators', () => {
  const render = admin => renderToStaticMarkup(createElement(SoftwareStatus, { user: {username:'alice', csrf:'fixture', admin, addresses:[]} }));
  const user = render(false);
  assert.match(user, /Loading version/);
  assert.doesNotMatch(user, /Software updates|Check for updates|checkbox/);
  const admin = render(true);
  assert.match(admin, /Software updates/);
  assert.match(admin, /Automatically check while this console is open/);
  assert.doesNotMatch(admin, /checked=""/);
  assert.match(admin, /Installation remains a server operation/);
});
