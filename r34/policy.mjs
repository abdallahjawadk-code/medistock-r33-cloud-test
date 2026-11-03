import assert from 'node:assert/strict';
export const REPOSITORY='abdallahjawadk-code/medistock-r33-cloud-test';
export const TARGET='eyrzxgfkvqybjdgyphap';
export const SYSTEM_IDENTIFIER='7642734024280108049';
export const SOURCE_HEAD='0b5f1226591e6eea5408f9603e29e3e8890b15bb';
export const MANIFEST_SHA256='ae8d6464179604d4b55100784b61435b119a21d23a3fb38d682cf38c0f6bc503';
export function authorize(e){
 assert.equal(e.GITHUB_REPOSITORY,REPOSITORY,'REPOSITORY');
 assert.equal(e.GITHUB_EVENT_NAME,'workflow_dispatch','MANUAL_ONLY');
 assert.equal(e.GITHUB_ACTOR,'abdallahjawadk-code','OWNER_ONLY');
 assert.equal(e.GITHUB_TRIGGERING_ACTOR,'abdallahjawadk-code','TRIGGERING_OWNER_ONLY');
 assert.equal(e.GITHUB_REF,'refs/heads/master','MASTER_ONLY');
 for(const key of ['GITHUB_SHA','R34_APPROVED_SHA','R34_INPUT_SHA'])assert.match(e[key]||'',/^[a-f0-9]{40}$/,'FULL_COMMIT_REQUIRED');
 assert.equal(e.GITHUB_SHA,e.R34_APPROVED_SHA,'REVIEWED_COMMIT');
 assert.equal(e.R34_INPUT_SHA,e.GITHUB_SHA,'INPUT_COMMIT');
 assert.equal(e.GITHUB_RUN_ATTEMPT,'1','NO_AUTOMATIC_REPLAY');
}
export function endpoint(host,user){
 if(host===`db.${TARGET}.supabase.co`&&user==='postgres')return;
 assert.match(host||'',/^aws-\d+-ap-south-1\.pooler\.supabase\.com$/,'ACTUAL_CONNECT_SESSION_HOST');
 assert.equal(user,'postgres.'+TARGET,'PRODUCTION_SESSION_USER');
}
export function identity(value){
 assert.equal(value.system_identifier,SYSTEM_IDENTIFIER,'PRODUCTION_IDENTITY');
 assert.equal(value.database,'postgres','DATABASE');
 assert.equal(value.server_version_num,170006,'REQUALIFY_VERSION_DRIFT');
 assert.equal(value.ssl_verify_full,true,'TLS_REQUIRED');
}
export function quota(receipt,now=Date.now()){
 assert.equal(receipt.owner_confirmed,true,'OWNER_QUOTA_RECEIPT');
 assert.equal(receipt.target,TARGET,'QUOTA_TARGET');
 assert.equal(receipt.storage_class,'Standard','STANDARD_ONLY');
 assert.equal(receipt.additional_spend_authorized_usd,0,'NO_PAID_RESOURCE');
 const age=now-Date.parse(receipt.checked_at);assert.ok(age>=0&&age<3600000,'FRESH_QUOTA_RECEIPT');
 assert.ok(Number.isSafeInteger(receipt.r2_free_bytes_remaining)&&receipt.r2_free_bytes_remaining>=1073741824,'R2_FREE_CAPACITY');
 assert.ok(Number.isSafeInteger(receipt.supabase_egress_bytes_remaining)&&receipt.supabase_egress_bytes_remaining>=1073741824,'SOURCE_FREE_EGRESS');
 assert.ok(receipt.r2_free_class_a_remaining>=100&&receipt.r2_free_class_b_remaining>=100,'FREE_OPERATIONS');
}
