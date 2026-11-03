// Review-only until independently authorized for publication/dispatch.
// No PostgreSQL client TCP connection, hosted credentials, or hosted execution path.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawn} from 'node:child_process';import {fileURLToPath} from 'node:url';
import {align,bodyMD5} from './align-chain.mjs';import {patchP3A1,sha} from './p3a1-compat-patch.mjs';import {isolationFlags,verifyIsolation} from './runtime-policy.mjs';import {runJourney} from './chain-journey.mjs';
const e=process.env,here=path.dirname(fileURLToPath(import.meta.url)),app=path.join(e.GITHUB_WORKSPACE||'', 'app');
const image='supabase/postgres:17.11.0.003@sha256:7374d196da7e301512cc5329e18040e0f7bb856287b323777cdadecccbc6c7e4';
const name='r33-chain-'+e.GITHUB_RUN_ID+'-'+e.GITHUB_RUN_ATTEMPT;
const pins=JSON.parse(fs.readFileSync(path.join(here,'CLOUD_SOURCE_PINS.json'))),review=JSON.parse(fs.readFileSync(path.join(here,'CHAIN_REVIEW_MANIFEST.json')));
const checks=[],steps=[];let created=false,stage='AUTHORIZATION',identity;
async function docker(args,input,allowFailure=false){return await new Promise((resolve,reject)=>{
 const p=spawn('docker',args,{stdio:['pipe','pipe','pipe']});const out=[],err=[];let length=0;
 for(const [stream,list] of [[p.stdout,out],[p.stderr,err]])stream.on('data',b=>{length+=b.length;if(length>16*1024*1024){p.kill();reject(Error('OUTPUT_LIMIT'));}else list.push(b);});
 p.on('error',()=>reject(Error('DOCKER_EXEC_FAILED')));p.on('close',code=>{const r={code,out:Buffer.concat(out).toString(),err:Buffer.concat(err).toString()};if(code===0||allowFailure)resolve(r);else reject(Error('DOCKER_COMMAND_FAILED'));});p.stdin.on('error',()=>{});p.stdin.end(input);
});}
async function sql(text,allowFailure=false){
 const r=await docker(['exec','-i',name,'psql','-X','-qAt','-h','/tmp','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-v','VERBOSITY=terse'],text,true);
 if(r.code!==0&&!allowFailure){console.error(JSON.stringify({synthetic_error:r.err.split('\n').find(l=>l.startsWith('ERROR:'))?.slice(0,400)}));throw Error('ISOLATED_SQL_FAILED');}return r;
}
const query=async q=>JSON.parse((await sql("SELECT coalesce(json_agg(x),'[]'::json) FROM ("+q+') x;')).out.trim());
async function check(label,fn){stage=label;await fn();checks.push(label);console.log('PASS '+label);}
function source(p){assert.ok(Object.hasOwn(pins.pins,p),'UNPINNED_SOURCE');const b=fs.readFileSync(path.join(app,p));for(const bytes of [b,Buffer.from(b.toString().replace(/\r\n/g,'\n')),Buffer.from(b.toString().replace(/\r\n/g,'\n').replace(/\n/g,'\r\n'))])if(sha(bytes)===pins.pins[p])return bytes.toString();throw Error('PUBLIC_SOURCE_DRIFT:'+p);}
const roleFP=async()=>query("SELECT md5((SELECT jsonb_agg(to_jsonb(r) ORDER BY rolname)::text FROM pg_roles r)) roles,md5((SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor)::text FROM pg_auth_members m)) memberships");
const sealNames=['phoenix_private.central_needs_capability_breaches_v1()','phoenix_r2.capability_breaches()','phoenix_c4.capability_breaches_v1()','phoenix_monthly.capability_breaches_v1()'];
async function seals(){for(const sig of sealNames)if((await query(`SELECT to_regprocedure('${sig}') IS NOT NULL present`))[0].present)assert.deepEqual(await query('SELECT * FROM '+sig),[],sig);}
async function stock(){const result=[];for(const t of ['warehouse_stock','warehouse_stock_movements','outlet_stock','outlet_stock_movements','warehouse_dispatches','warehouse_dispatch_lines','phoenix_movement_events']){
 const data=await query(`SELECT to_jsonb(t) row FROM public.${t} t ORDER BY to_jsonb(t)::text`);
 const defs=await query(`SELECT pg_get_functiondef(p.oid) definition,p.proacl::text acl,p.prosecdef,p.proconfig FROM pg_proc p WHERE p.prosrc ~* '(insert[[:space:]]+into|update|delete[[:space:]]+from|truncate)[[:space:]]+(public[.])?"?${t}\\M' OR p.proname ~* 'fefo' ORDER BY p.oid::regprocedure::text`);
 result.push({table:t,rows:data.length,data_sha256:sha(JSON.stringify(data)),writers_sha256:sha(JSON.stringify(defs))});}return result;}
async function negative(label,tamper,seal){await check(label,async()=>{
 const r=await sql(`BEGIN;${tamper};DO $negative$ BEGIN IF NOT EXISTS(SELECT 1 FROM ${seal}) THEN RAISE EXCEPTION 'NEGATIVE_GUARD_MISSED'; END IF;END $negative$;ROLLBACK;`,true);
 assert.equal(r.code,0,r.err.slice(0,400));await seals();});}
async function centralNegatives(suffix){
 for(const [label,tamper] of [
 ['ANON_SELECT','GRANT SELECT ON public.central_needs_catalog_years TO anon'],
 ['AUTH_COLUMN','GRANT SELECT(planning_year) ON public.central_needs_catalog_years TO authenticated'],
 ['API_SET_MANAGED','GRANT supabase_read_only_user TO anon WITH INHERIT FALSE'],
 ['API_INHERIT_MANAGED','GRANT supabase_etl_admin TO authenticated'],
 ['UNKNOWN_READER','CREATE ROLE unexpected_reader NOLOGIN BYPASSRLS;GRANT pg_read_all_data TO unexpected_reader'],
 ['EXPLICIT_MANAGED_SELECT','GRANT SELECT ON public.central_needs_catalog_years TO supabase_read_only_user'],
 ['INHERITED_APP_SELECT','CREATE ROLE app_reader NOLOGIN;GRANT SELECT ON public.central_needs_catalog_years TO app_reader;GRANT app_reader TO supabase_etl_admin'],
 ['MANAGED_COLUMN','GRANT SELECT(planning_year) ON public.central_needs_catalog_years TO supabase_etl_admin'],
 ['PUBLIC_SELECT','GRANT SELECT ON public.central_needs_catalog_years TO PUBLIC'],
 ['MANAGED_RPC','GRANT EXECUTE ON FUNCTION phoenix_private.annual_catalog_trim_v1(text) TO supabase_etl_admin'],
 ['MANAGED_WRITE_ALL','GRANT pg_write_all_data TO supabase_etl_admin'],
 ['MANAGED_INSERT','GRANT INSERT ON public.central_needs_catalog_years TO supabase_etl_admin'],
 ['MANAGED_TRIGGER','GRANT TRIGGER ON public.central_needs_catalog_years TO supabase_etl_admin'],
 ['MANAGED_SCHEMA_CREATE','GRANT CREATE ON SCHEMA phoenix_private TO supabase_etl_admin'],
 ['RLS_DISABLED','ALTER TABLE public.central_needs_catalog_years DISABLE ROW LEVEL SECURITY'],
 ['RESTRICTIVE_POLICY_REMOVED','DROP POLICY r1_actor_scope_restrictive ON public.central_needs_catalog_years'],
 ['PROFILE_DRIFT','ALTER ROLE supabase_etl_admin NOREPLICATION'],
 ['MEMBERSHIP_DRIFT','GRANT pg_read_all_data TO supabase_etl_admin WITH ADMIN TRUE GRANTED BY supabase_admin'],
 ])await negative(suffix+'_'+label,tamper,sealNames[0]);
}
async function privateNegatives(schema,seal){
 const t=schema==='phoenix_c4'?'proofs':'policy_references';
 for(const [label,tamper] of [
 ['ANON_SCHEMA','GRANT USAGE ON SCHEMA '+schema+' TO anon'],
 ['MANAGED_EXPLICIT_USAGE','GRANT USAGE ON SCHEMA '+schema+' TO supabase_etl_admin'],
 ['MANAGED_CREATE','GRANT CREATE ON SCHEMA '+schema+' TO supabase_etl_admin'],
 ['PUBLIC_USAGE','GRANT USAGE ON SCHEMA '+schema+' TO PUBLIC'],
 ['MANAGED_TABLE_SELECT',`GRANT SELECT ON ${schema}.${t} TO supabase_read_only_user`],
 ['MANAGED_COLUMN_SELECT',`GRANT SELECT(id) ON ${schema}.${t} TO supabase_etl_admin`],
 ['MANAGED_INHERITED_SELECT',`CREATE ROLE inherited_app NOLOGIN;GRANT SELECT ON ${schema}.${t} TO inherited_app;GRANT inherited_app TO supabase_etl_admin`],
 ['PUBLIC_TABLE_SELECT',`GRANT SELECT ON ${schema}.${t} TO PUBLIC`],
 ['AUTH_TABLE_SELECT',`GRANT SELECT ON ${schema}.${t} TO authenticated`],
 ['MANAGED_WRITE',`GRANT INSERT ON ${schema}.${t} TO supabase_etl_admin`],
 ['MANAGED_TRIGGER',`GRANT TRIGGER ON ${schema}.${t} TO supabase_etl_admin`],
 ['MANAGED_MAINTAIN',`GRANT MAINTAIN ON ${schema}.${t} TO supabase_etl_admin`],
 ['NOINHERIT_MAINTAIN_ALIAS','CREATE ROLE maintenance_alias NOLOGIN;GRANT pg_maintain TO maintenance_alias WITH INHERIT FALSE'],
 ['API_SET_MAINTAIN','GRANT pg_maintain TO authenticated WITH INHERIT FALSE'],
 ['MANAGED_EXECUTE',`GRANT EXECUTE ON FUNCTION ${seal} TO supabase_etl_admin`],
 ['UNKNOWN_READER','CREATE ROLE unexpected_reader NOLOGIN BYPASSRLS;GRANT pg_read_all_data TO unexpected_reader'],
 ['API_SET_MANAGED','GRANT supabase_read_only_user TO authenticated WITH INHERIT FALSE'],
 ['MANAGED_WRITE_ALL','GRANT pg_write_all_data TO supabase_etl_admin'],
 ['PROFILE_DRIFT','ALTER ROLE supabase_etl_admin NOREPLICATION'],
 ['RLS_DISABLED',`ALTER TABLE ${schema}.${t} DISABLE ROW LEVEL SECURITY`],
 ['UNREGISTERED_TABLE',`CREATE TABLE ${schema}.unregistered(id integer)`],
 ])await negative(schema+'_'+label,tamper,seal);
 await check(schema+'_EMPTY_COLUMN_ACL',async()=>{await sql(`BEGIN;GRANT SELECT(id) ON ${schema}.${t} TO supabase_etl_admin;REVOKE SELECT(id) ON ${schema}.${t} FROM supabase_etl_admin;DO $empty$ BEGIN IF EXISTS(SELECT 1 FROM ${seal}) THEN RAISE EXCEPTION 'EMPTY_ACL_REJECTED';END IF;END $empty$;ROLLBACK;`);await seals();});
}
try{
 assert.equal(e.GITHUB_REPOSITORY,'abdallahjawadk-code/medistock-r33-cloud-test');assert.equal(e.GITHUB_ACTOR,'abdallahjawadk-code');assert.equal(e.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(e.GITHUB_REF,'refs/heads/master');
 assert.equal(e.R33_APPROVED_CHAIN_SHA,e.GITHUB_SHA);assert.equal(e.RUNNER_ENVIRONMENT,'github-hosted');assert.equal(e.RUNNER_OS,'Linux');assert.equal(process.platform,'linux');assert.notEqual(e.RUNNER_DEBUG,'1');
 assert.equal(review.hosted_apply_authorized,false);assert.equal(pins.hosted_connections_allowed,false);
 // Verify ALL public source bytes and candidates BEFORE initializing a database.
 for(const p of Object.keys(pins.pins))source(p);
 const accepted=Buffer.from(patchP3A1(Buffer.from(source(pins.original_manifest.steps[7].path))).sql);
 const aligned=align(pins.original_manifest,app,accepted);
 for(const r of aligned)assert.equal(r.sha256,review.steps.find(x=>x.order===r.order).sha256);
 stage='ISOLATED_POSTGRES_IMAGE';await docker(['pull',image]);const meta=JSON.parse((await docker(['image','inspect',image])).out)[0];assert.ok(meta.RepoDigests.some(x=>x.endsWith('@'+image.split('@')[1])));
 const ids=(await docker(['run','--rm','--network','none','--read-only','--user','postgres','--entrypoint','/bin/sh',image,'-c','id -u;id -g'])).out.trim().split('\n');
 await docker(['run','-d','--name',name,...isolationFlags(...ids),'--user','postgres','--entrypoint','/bin/bash',image,'-c',fs.readFileSync(path.join(here,'chain-runtime.sh'),'utf8')]);created=true;
 let ready=false;for(let i=0;i<60;i++){if((await docker(['exec',name,'test','-f','/tmp/R33_READY'],null,true)).code===0){ready=true;break;}await new Promise(r=>setTimeout(r,500));}assert.ok(ready);
 verifyIsolation(JSON.parse((await docker(['inspect',name])).out)[0],...ids);
 identity=(await query("SELECT current_setting('server_version') version,(SELECT system_identifier::text FROM pg_control_system()) id"))[0];assert.equal(identity.version,'17.11');assert.notEqual(identity.id,'7692131729119822239');
 stage='RECONSTRUCT_AFTER_SEVEN';await sql(source(pins.aux[0]));await sql(pins.bootstrap_acl_alignment.join(';')+';');
 for(const row of pins.baseline){const n=Number(path.basename(row.path).slice(0,3));if(n===4)continue;let text=source(row.path);
  if(n===23){assert.equal((text.match(/SELECT\s+qual\s+INTO/gi)||[]).length,3);text=text.replace(/SELECT\s+qual\s+INTO/gi,'SELECT coalesce(qual, with_check) INTO');assert.equal(sha(text),'28705f920aba8d809cdc4f6bc98183eb6770cb8a3e988f48940146aa13a24a9f');}
  if(n===85){const verified=await query(source(pins.aux[2]).trim().replace(/;$/,''));assert.ok(verified.length>0&&verified.every(r=>r.ok===true),'M085_PRECONDITIONS_FAILED');text="SET phoenix.availability_cutover_attested='true';\n"+text+'\nRESET phoenix.availability_cutover_attested;';}
  await sql(text);if(n===1)await sql(pins.synthetic_seed_after001);if(n===182)await sql(source(pins.aux[1]));
 }
 for(const row of pins.canonical230)await sql(source(row.path));
 await check('CANONICAL230_FUNCTION_BODY_ACL_REFERENCE',async()=>{
  for(const r of pins.convergence_reference){const got=(await query(`SELECT md5(prosrc) body_md5,prosecdef definer,provolatile volatility,proconfig config,has_function_privilege('anon',oid,'EXECUTE') execute_anon,has_function_privilege('authenticated',oid,'EXECUTE') execute_authenticated,has_function_privilege('service_role',oid,'EXECUTE') execute_service_role FROM pg_proc WHERE oid=to_regprocedure('${r.sig}')`))[0];
   for(const k of ['body_md5','definer','volatility','config','execute_anon','execute_authenticated','execute_service_role'])assert.deepEqual(got[k],r[k],r.sig+':'+k);}
 });
 for(const step of pins.original_manifest.steps.filter(x=>x.order>=2&&x.order<=7))await sql(source(step.path));
 await sql(`CREATE ROLE supabase_admin NOLOGIN SUPERUSER;CREATE ROLE supabase_etl_admin LOGIN INHERIT BYPASSRLS REPLICATION;CREATE ROLE supabase_read_only_user LOGIN INHERIT BYPASSRLS;ALTER ROLE supabase_read_only_user SET default_transaction_read_only=on;GRANT pg_read_all_data TO supabase_admin WITH ADMIN OPTION;GRANT pg_read_all_data TO supabase_etl_admin,supabase_read_only_user GRANTED BY supabase_admin;`);
 await check('AFTER7_FULL_SCHEMA_P1_SEAL_AND_ABSENT8',async()=>{assert.equal((await query("SELECT md5(prosrc) h FROM pg_proc WHERE oid='phoenix_private.central_needs_capability_breaches_v1()'::regprocedure"))[0].h,'a0bd1f740bcc96adfb074073a9b2f587');assert.equal((await query("SELECT to_regclass('public.central_needs_catalog_years') IS NULL absent"))[0].absent,true);await seals();});
 const rolesBefore=await roleFP(),stockBefore=await stock();
 for(const row of aligned){stage='FULL_FILE_'+row.order;
  // Execute exactly the reviewed bytes: no injected diagnostics, altered
  // verification, stripped transaction, or updated body pins at execution time.
  assert.equal(sha(row.sql),row.sha256);
  const applied=await sql(row.sql,true);
  if(applied.code!==0){console.error(JSON.stringify({synthetic_error:applied.err.split('\n').find(l=>l.startsWith('ERROR:'))?.slice(0,400)}));throw Error('ISOLATED_SQL_FAILED');}
  steps.push({order:row.order,sha256:row.sha256,executed_sha256:sha(row.sql),result:'PASS_FULL_FILE_DISPOSABLE'});console.log('PASS FULL_FILE_'+row.order);
  if([13,15].includes(row.order)){const own=row.order===13?sealNames[2]:sealNames[3];console.log(JSON.stringify({diagnostic_only:true,step:row.order,central:await query('SELECT * FROM '+sealNames[0]),own:await query('SELECT * FROM '+own)}));}
  await check('AFTER'+row.order+'_ALL_SEALS_ROLES_STOCK',async()=>{await seals();assert.deepEqual(await roleFP(),rolesBefore);assert.deepEqual(await stock(),stockBefore);
   assert.equal((await query("SELECT md5(prosrc) h FROM pg_proc WHERE oid='phoenix_private.central_needs_capability_breaches_v1()'::regprocedure"))[0].h,row.central_seal_body_md5);});
  if([8,9,10].includes(row.order))await centralNegatives('AFTER'+row.order);
  if(row.order===13){
   await check('PG17_MAINTAIN_BUILTIN_SELF_EXPLAINS_PREVIOUS_GUARD_FAILURE',async()=>{
    const builtin=(await query("SELECT rolcanlogin,has_table_privilege(oid,'phoenix_c4.proofs','MAINTAIN') intrinsic_maintain FROM pg_roles WHERE oid='pg_maintain'::regrole"))[0];
    assert.equal(builtin.rolcanlogin,false);assert.equal(builtin.intrinsic_maintain,true);await seals();
   });
   await privateNegatives('phoenix_c4',sealNames[2]);
  }
  if(row.order===15)await privateNegatives('phoenix_monthly',sealNames[3]);
 }
 await runJourney({sql,query,check,seals,stock});
 await check('FINAL_ROLES_AND_STOCK_UNCHANGED',async()=>{assert.deepEqual(await roleFP(),rolesBefore);assert.deepEqual(await stock(),stockBefore);await seals();});
 console.log(JSON.stringify({result:'PASS_FULL_CHAIN_8_15_ISOLATED',identity,steps,checks,hosted_connections:0,fixture_scope:pins.fixture_scope,auth_transport:'SQL auth.uid shim only, not hosted JWT/Auth acceptance',stock_fixture_scope:'actual stock tables/writer definitions fingerprinted; row counts recorded, no FEFO SEND/RECEIVE acceptance claimed',stock_before:stockBefore}));
}catch(err){console.error(JSON.stringify({result:'HOLD',stage,error:err.message,identity,completed_steps:steps,checks_passed:checks}));process.exitCode=1;}
finally{if(created)await docker(['rm','-f','-v',name],null,true);}
