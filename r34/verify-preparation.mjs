// Credential-free source qualification only. No hosted database or backup client.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';import {fileURLToPath} from 'node:url';
import {authorize,MANIFEST_SHA256,SOURCE_HEAD,TARGET} from './policy.mjs';
import {align} from '../chain/align-chain.mjs';import {patchP3A1} from '../chain/p3a1-compat-patch.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));const sha=b=>createHash('sha256').update(b).digest('hex');
export function buildSources(app){
 const bytes=fs.readFileSync(path.join(here,'R34_RELEASE_MANIFEST.json'));assert.equal(sha(bytes),MANIFEST_SHA256);
 const m=JSON.parse(bytes);assert.equal(m.target,TARGET);assert.equal(m.source_head,SOURCE_HEAD);assert.equal(m.apply_authorized,false);assert.equal(m.steps.length,13);
 const source=JSON.parse(fs.readFileSync(path.join(here,'../chain/CLOUD_SOURCE_PINS.json')));assert.equal(source.source_head,SOURCE_HEAD);
 const original=source.original_manifest;const a1=original.steps.find(s=>s.order===8);const accepted=patchP3A1(fs.readFileSync(path.join(app,a1.path))).sql;
 const modified=align(original,app,Buffer.from(accepted));
 const files=[];
 for(const s of m.steps){
  const bytes=s.former_r33_order<8?fs.readFileSync(path.join(app,original.steps.find(o=>o.order===s.former_r33_order).path)):Buffer.from(modified.find(o=>o.order===s.former_r33_order).sql);
  assert.equal(sha(bytes),s.sha256,'SOURCE_'+s.order);assert.ok(s.former_r33_order>=3);files.push({...s,bytes});
 }
 return files;
}
export function verify(app){buildSources(app);return {status:'PASS_R34_PREPARATION_SOURCE_ONLY',files:13,backup:'NOT_RUN',restore:'NOT_RUN',production_sql:false};}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 authorize(process.env);const app=path.resolve(process.env.R34_APP_SOURCE||'app');
 // Source checkout is pinned in the workflow. No paths/commands from dispatch inputs.
 console.log(JSON.stringify(verify(app)));
}
