import assert from 'node:assert/strict';import {randomUUID} from 'node:crypto';
const literal=v=>v===null?'NULL':typeof v==='number'?String(v):"'"+(typeof v==='object'?JSON.stringify(v):String(v)).replaceAll("'","''")+"'";
export async function runJourney({sql,query,check,seals,stock}){
 const F={owner:randomUUID(),other:randomUUID(),beneficiary:randomUUID(),actor:randomUUID(),outsider:randomUUID()};
 const before=await stock();
 async function as(actor,statement){const r=await sql(`BEGIN;SET LOCAL ROLE authenticated;SELECT set_config('request.jwt.claim.sub',${literal(actor||'')},true);SELECT coalesce(json_agg(r),'[]'::json) FROM (${statement}) r;COMMIT;`,true);
  if(r.code!==0)throw Error(r.err);return JSON.parse(r.out.split('\n').find(l=>l.startsWith('[')));}
 const call=async(name,args=[],actor=F.actor)=>(await as(actor,`SELECT public.${name}(${args.map(literal).join(',')}) value`))[0].value;
 const rpc=async(name,args=[],actor=F.actor)=>call('phoenix_central_needs_'+name,args,actor);
 await sql(`INSERT INTO public.organizations(id,name,name_ar,code,organization_kind,institution_class,status) VALUES
 (${literal(F.owner)},'Chain synthetic PDA','جهة اختبار',${literal('chain-'+F.owner)},'pharmacy_department_authority',NULL,'active'),
 (${literal(F.other)},'Chain other PDA','جهة أخرى',${literal('chain-'+F.other)},'pharmacy_department_authority',NULL,'active'),
 (${literal(F.beneficiary)},'Chain synthetic hospital','مستشفى اختبار',${literal('chain-'+F.beneficiary)},'care_institution','hospital','active');`);
 for(const [actor,org] of [[F.actor,F.owner],[F.outsider,F.other]]){
  await sql(`INSERT INTO auth.users(id,email) VALUES(${literal(actor)},${literal(actor+'@fixture.invalid')});UPDATE public.profiles SET organization_id=${literal(org)},role='warehouse_officer',status='active',full_name='Synthetic chain employee' WHERE id=${literal(actor)};`);
  for(const key of ['view','edit','manual_need.set','approve','material_review','allocation.view'])await sql(`INSERT INTO public.profile_permission_overrides(profile_id,permission_key,allowed) VALUES(${literal(actor)},${literal('central_needs.'+key)},true);`);
 }
 await sql(`SELECT phoenix_private.central_needs_activate_manual_cutover_v1(${literal(F.owner)});`);
 const inserted=await sql(`INSERT INTO public.central_items(name,name_ar,national_code,dosage_form,concentration,unit,status) VALUES('Chain synthetic item','مادة اختبار','00012-A','Capsules','500 mg','box','active') RETURNING id;`);
 const itemId=inserted.out.trim();assert.match(itemId,/^[a-f0-9-]{36}$/);
 await rpc('open_catalog_year',[F.owner,2026,'chain-open-'+randomUUID()]);
 const preview=await rpc('preview_annual_canonical',[F.owner,2026,itemId]);
 const member=await rpc('add_annual_catalog_item',[F.owner,2026,itemId,preview.canonicalFingerprint,[],'Explicit synthetic annual member','chain-add-'+randomUUID()]);
 const annual=member.membership.annualItemId,version=member.fieldVersion.fieldVersionId;
 const revision=(await rpc('open_dossier',[F.owner,2026,'chain-medicines','اختبار الأدوية'])).plan_revision_id;
 await check('CHAIN_SEARCH_TEXT_IDENTITY_NO_AUTO_QUANTITY',async()=>{
  const r=await rpc('search_annual_catalog',[F.owner,2026,'00012-A',25,null]);assert.equal(r.items.length,1);
  assert.equal(r.items[0].fieldVersion.fields.nationalCode.value,'00012-A');assert.equal(r.items[0].fieldVersion.fields.unit.value,'box');
  assert.equal((await query('SELECT count(*)::int n FROM public.central_needs_manual_need_events'))[0].n,0);
 });
 const args=[F.owner,2026,revision,F.beneficiary,itemId,null,'1200','Explicit manual annual quantity','chain-need-'+randomUUID(),null,null,annual,version];
 await check('CHAIN_BENEFICIARY_REQUIRED',async()=>{const missing=[...args];missing[3]=null;await assert.rejects(rpc('add_annual_need_line',missing),/beneficiary|scope|invalid|missing|required/i);});
 await check('CHAIN_MANUAL_ANNUAL_SAVE_READ_REPLAY',async()=>{
  await rpc('add_annual_need_line',args);const repeat=await rpc('add_annual_need_line',args);assert.equal(repeat.idempotentReplay,true);
  const r=await rpc('list_annual_need_events',[F.owner,2026,revision,50,null]);assert.equal(r.events.length,1);assert.equal(r.events[0].quantityText,'1200');assert.equal(r.events[0].beneficiaryOrganizationId,F.beneficiary);
 });
 await check('CHAIN_CROSS_OWNER_AND_NULL_ACTOR_REJECTED',async()=>{
  await assert.rejects(rpc('search_annual_catalog',[F.owner,2026,'00012-A',25,null],F.outsider),/forbidden|scope|authorized/i);
  await assert.rejects(rpc('search_annual_catalog',[F.owner,2026,'00012-A',25,null],null),/authenticated|forbidden/i);
 });
 await check('CHAIN_EXCEL_WITHDRAWAL_SOD_PRESERVED',async()=>{
  const dossier=await rpc('open_dossier',[F.owner,2027,'chain-sod','حارس فصل المهام']);
  await assert.rejects(rpc('withdraw_draft_revision',[dossier.plan_revision_id,dossier.plan_revision_id,'Synthetic withdrawal','chain-reference']),/separation_of_duties/);
 });
 await check('CHAIN_R2_DEFAULT_DENY_AND_NO_OPERATIONAL_WRITES',async()=>{
  const r=await call('phoenix_r2_capabilities',[F.owner]);assert.equal(r.operationalWritesImplemented,false);assert.equal(r.authorityActivated,false);assert.equal(r.create,false);assert.equal(r.approve,false);
 });
 const monthly=()=>call('phoenix_monthly_policy_reference',[F.owner,2026,annual,version,itemId,F.beneficiary]);
 await check('CHAIN_MONTHLY_NO_FABRICATED_REFERENCE',async()=>{const r=await monthly();assert.equal(r.status,'awaiting_policy');});
 const policy={policyId:randomUUID(),version:1,status:'approved',context:{ownerOrgId:F.owner,planningYear:2026,annualItemId:annual,fieldVersionId:version,canonicalItemId:itemId,unit:'box',beneficiaryOrganizationId:F.beneficiary},unitStep:'1',eligibleMonths:Array.from({length:12},(_,i)=>i+1),fixedMonths:[],basis:{beneficiaryOrganizationId:F.beneficiary,documentReference:'SYNTHETIC ONLY',documentSha256:'b'.repeat(64),periodReference:'Synthetic months',priorAllocationStatus:'none_verified',ledgerSnapshotSha256:'c'.repeat(64),approvedById:F.actor,approvedByName:'Synthetic employee',approvedAt:'2026-11-03T00:00:00.000Z'}};
 await sql(`SELECT phoenix_monthly.publish_reference_v1(${literal(policy)}::jsonb,NULL,true);`);
 await check('CHAIN_MONTHLY_REFERENCE_NON_EFFECTIVE',async()=>{const r=await monthly();assert.equal(r.status,'ready');assert.equal(r.effectiveAllocation,false);assert.equal(r.draftJournalImplemented,false);});
 await check('CHAIN_RLS_DENIES_ROWS_AFTER_GRANT_TAMPER',async()=>{
  const r=await sql(`BEGIN;GRANT SELECT ON public.central_needs_catalog_years TO authenticated;SET LOCAL ROLE authenticated;SELECT set_config('request.jwt.claim.sub',${literal(F.outsider)},true);SELECT count(*) FROM public.central_needs_catalog_years;ROLLBACK;`);
  assert.equal(r.out.trim().split('\n').at(-1),'0');await seals();
 });
 await check('CHAIN_STOCK_DATA_AND_FEFO_WRITERS_UNCHANGED',async()=>assert.deepEqual(await stock(),before));
}
