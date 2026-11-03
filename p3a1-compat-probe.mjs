import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';import {patchP3A1,extractSeal,sha} from './p3a1-compat-patch.mjs';
import {isolationFlags,verifyIsolation} from './runtime-policy.mjs';
const e=process.env,here=path.dirname(fileURLToPath(import.meta.url));
const image='supabase/postgres:17.11.0.003@sha256:7374d196da7e301512cc5329e18040e0f7bb856287b323777cdadecccbc6c7e4';
const name='r33-p3a1-'+e.GITHUB_RUN_ID+'-'+e.GITHUB_RUN_ATTEMPT;let created=false,stage='AUTHORIZATION';
async function docker(args,input,allowFailure=false){return await new Promise((resolve,reject)=>{
 const p=spawn('docker',args,{stdio:['pipe','pipe','pipe']});const parts=[],errors=[];let length=0;
 p.stdout.on('data',b=>{length+=b.length;assert.ok(length<4*1024*1024);parts.push(b);});p.stderr.on('data',b=>errors.push(b));
 p.on('error',()=>reject(Error('NATIVE_START')));p.on('close',code=>{const result={code,out:Buffer.concat(parts).toString(),err:Buffer.concat(errors).toString()};if(code===0||allowFailure)resolve(result);else reject(Error('NATIVE_FAILED'));});p.stdin.on('error',()=>{});p.stdin.end(input);
});}
async function sql(text,allowFailure=false){return docker(['exec','-i',name,'psql','-X','-h','/tmp','-U','r33_isolated_restore','-d','postgres','-At','-v','ON_ERROR_STOP=1'],text,allowFailure);}
const query=async q=>JSON.parse((await sql('SELECT coalesce(json_agg(r),\'[]\'::json) FROM ('+q+') r;')).out.trim());
const seals=async()=>query('SELECT b FROM phoenix_private.central_needs_capability_breaches_v1() b');
const manifest=s=>[...s.match(/  manifest\(relname\) AS \(([\s\S]*?)\n  \),\n  cn AS/)[1].matchAll(/'([^']+)'/g)].map(x=>x[1]);
const signatures=s=>[...s.match(/  acl_manifest\(sig\) AS \(([\s\S]*?)\n  \),/)[1].matchAll(/'([^']+\([^']*\))'/g)].map(x=>x[1]);
const table=n=>`CREATE TABLE public.${n}(id integer,owner_org uuid); ALTER TABLE public.${n} ENABLE ROW LEVEL SECURITY; ALTER TABLE public.${n} FORCE ROW LEVEL SECURITY; CREATE POLICY r1_actor_scope_restrictive ON public.${n} AS RESTRICTIVE TO authenticated USING(false) WITH CHECK(false); INSERT INTO public.${n} VALUES(1,'00000000-0000-4000-8000-000000000001');`;
const roleFP=async()=>query("SELECT md5((SELECT jsonb_agg(to_jsonb(r) ORDER BY rolname)::text FROM pg_roles r)) roles,md5((SELECT jsonb_agg(to_jsonb(a) ORDER BY roleid,member,grantor)::text FROM pg_auth_members a)) memberships");
const checks=[];async function check(label,fn){stage=label;await fn();checks.push(label);console.log('PASS '+label);}
try{
 assert.equal(e.GITHUB_REPOSITORY,'abdallahjawadk-code/medistock-r33-cloud-test');assert.equal(e.GITHUB_ACTOR,'abdallahjawadk-code');assert.equal(e.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(e.GITHUB_REF,'refs/heads/master');
 assert.equal(e.R33_APPROVED_TOOLS_SHA,e.GITHUB_SHA);assert.equal(e.RUNNER_ENVIRONMENT,'github-hosted');assert.equal(e.RUNNER_OS,'Linux');assert.equal(process.platform,'linux');assert.notEqual(e.RUNNER_DEBUG,'1');
 const app=path.join(e.GITHUB_WORKSPACE,'app'),original=fs.readFileSync(path.join(app,'supabase/candidates/P3A1_annual_catalog_NOT_APPLIED.sql')),p1=fs.readFileSync(path.join(app,'supabase/candidates/P1_dossier_workbook_reservation_NOT_APPLIED.sql'));
 assert.equal(sha(p1),'d0f914e47b559fa027e9372beb17dc5cc4fe46affee29b480149b5a3be9440ff');const patch=patchP3A1(original);
 const oldSeal=extractSeal(original.toString()),newSeal=extractSeal(patch.sql),p1Seal=extractSeal(p1.toString());
 const annual=[...oldSeal.match(/annual_relations\(relname\) AS \(VALUES ([^\n]+)/)[1].matchAll(/'([^']+)'/g)].map(x=>x[1]);assert.equal(annual.length,8);
 stage='PINNED_IMAGE';await docker(['pull',image]);const meta=JSON.parse((await docker(['image','inspect',image])).out)[0];assert.ok(meta.RepoDigests.some(x=>x.endsWith('@'+image.split('@')[1])));
 const ids=(await docker(['run','--rm','--network','none','--read-only','--user','postgres','--entrypoint','/bin/sh',image,'-c','id -u;id -g'])).out.trim().split('\n');
 await docker(['run','-d','--name',name,...isolationFlags(...ids),'--user','postgres','--entrypoint','/bin/bash',image,'-c',fs.readFileSync(path.join(here,'cloud-runtime.sh'),'utf8')]);created=true;
 let ready=false;for(let i=0;i<60;i++){const x=await docker(['exec',name,'test','-f','/tmp/R33_READY'],null,true);if(x.code===0){ready=true;break;}await new Promise(r=>setTimeout(r,500));}assert.ok(ready);
 verifyIsolation(JSON.parse((await docker(['inspect',name])).out)[0],...ids);
 const identity=(await query("SELECT current_setting('server_version') version,(SELECT system_identifier::text FROM pg_control_system()) id"))[0];assert.equal(identity.version,'17.11');assert.notEqual(identity.id,'7692131729119822239');
 stage='SYNTHETIC_CATALOG_FIXTURE';
 await sql(`CREATE ROLE anon NOLOGIN; CREATE ROLE authenticated NOLOGIN; CREATE ROLE service_role NOLOGIN BYPASSRLS;
 CREATE ROLE supabase_admin NOLOGIN SUPERUSER;
 CREATE ROLE supabase_etl_admin LOGIN INHERIT BYPASSRLS REPLICATION;
 CREATE ROLE supabase_read_only_user LOGIN INHERIT BYPASSRLS;
 ALTER ROLE supabase_read_only_user SET default_transaction_read_only=on;
 SET ROLE supabase_admin; GRANT pg_read_all_data TO supabase_etl_admin,supabase_read_only_user; RESET ROLE;
 CREATE SCHEMA phoenix_private; CREATE SCHEMA phoenix_cn_policy;
 REVOKE ALL ON SCHEMA phoenix_private,phoenix_cn_policy FROM PUBLIC;
 REVOKE CREATE ON SCHEMA public FROM PUBLIC;`);
 const base=manifest(p1Seal);for(const n of base)await sql(table(n));
 await sql('CREATE TABLE phoenix_private.central_needs_lifecycle_attestations(id integer)');
 for(const sig of new Set([...signatures(p1Seal),...signatures(oldSeal)]))await sql(`CREATE FUNCTION ${sig} RETURNS integer LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $stub$ SELECT 1 $stub$; REVOKE ALL ON FUNCTION ${sig} FROM PUBLIC,anon,authenticated,service_role;`);
 await sql(p1Seal+" REVOKE ALL ON FUNCTION phoenix_private.central_needs_capability_breaches_v1() FROM PUBLIC,anon,authenticated,service_role;");
 const baselineRoles=await roleFP();
 await check('P1_PRESEAL_AND_HASH_MATCH_STAGING',async()=>{assert.deepEqual(await seals(),[]);assert.equal((await query("SELECT md5(prosrc) h FROM pg_proc WHERE oid='phoenix_private.central_needs_capability_breaches_v1()'::regprocedure"))[0].h,'a0bd1f740bcc96adfb074073a9b2f587');});
 await check('ORIGINAL_P3A1_POSTSEAL_REPRODUCES_AND_ROLLS_BACK',async()=>{
  const x=await sql('BEGIN;'+annual.map(table).join('\n')+oldSeal+`SELECT json_agg(b) FROM phoenix_private.central_needs_capability_breaches_v1() b;
  DO $verify$ BEGIN IF EXISTS(SELECT 1 FROM phoenix_private.central_needs_capability_breaches_v1()) THEN RAISE EXCEPTION 'P3A1_verify_failed: capability seal'; END IF; END $verify$;COMMIT;`,true);
  assert.notEqual(x.code,0);assert.ok(x.err.includes('P3A1_verify_failed: capability seal'));
  const breaches=JSON.parse(x.out.split('\n').find(l=>l.startsWith('[')));assert.equal(breaches.length,16);assert.ok(breaches.every(v=>v.includes('holds SELECT on RPC-only annual relation')));
  assert.equal((await query("SELECT to_regclass('public.central_needs_catalog_years') IS NULL absent"))[0].absent,true);assert.deepEqual(await seals(),[]);assert.deepEqual(await roleFP(),baselineRoles);
  console.log(JSON.stringify({original_failure_reproduced:true,breaches,annual_ddl_rolled_back:true}));
 });
 await sql('BEGIN;'+annual.map(table).join('\n')+newSeal+'COMMIT;');
 await check('COMPAT_SEAL_ACCEPTS_ONLY_MEASURED_MANAGED_INHERITED_READ',async()=>assert.deepEqual(await seals(),[]));
 await check('MANAGED_ROLE_MEMBERSHIPS_AND_ATTRIBUTES_UNCHANGED',async()=>assert.deepEqual(await roleFP(),baselineRoles));
 await check('PLATFORM_READ_VISIBILITY_EXISTS_BUT_NO_APPLICATION_WRITE',async()=>{
  for(const role of ['supabase_etl_admin','supabase_read_only_user']){
   const x=await sql(`BEGIN;SET LOCAL ROLE ${role};SELECT count(*) FROM public.central_needs_catalog_years;ROLLBACK;`);assert.ok(x.out.split('\n').includes('1'));
   assert.equal((await query(`SELECT has_table_privilege('${role}','public.central_needs_catalog_years','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') p`))[0].p,false);
  }
 });
 const negatives=[
  ['ANON_DIRECT_SELECT',"GRANT SELECT ON public.central_needs_catalog_years TO anon"],
  ['AUTH_COLUMN_SELECT',"GRANT SELECT(id) ON public.central_needs_catalog_years TO authenticated"],
  ['API_NO_INHERIT_SET_PLATFORM_ROLE',"GRANT supabase_read_only_user TO anon WITH INHERIT FALSE, SET TRUE"],
  ['AUTH_INHERITS_PLATFORM_ROLE',"GRANT supabase_etl_admin TO authenticated"],
  ['SERVICE_ROLE_SET_PLATFORM_ROLE',"GRANT supabase_read_only_user TO service_role WITH INHERIT FALSE, SET TRUE"],
  ['UNKNOWN_GLOBAL_READER',"CREATE ROLE unknown_reader NOLOGIN BYPASSRLS;GRANT pg_read_all_data TO unknown_reader"],
  ['MANAGED_EXPLICIT_SELECT',"GRANT SELECT ON public.central_needs_catalog_years TO supabase_read_only_user"],
  ['MANAGED_COLUMN_SELECT',"GRANT SELECT(id) ON public.central_needs_catalog_years TO supabase_etl_admin"],
  ['MANAGED_INHERITED_APP_SELECT',"CREATE ROLE extra_reader NOLOGIN;GRANT SELECT ON public.central_needs_catalog_years TO extra_reader;GRANT extra_reader TO supabase_etl_admin"],
  ['MANAGED_PRIVATE_EXECUTE',"GRANT EXECUTE ON FUNCTION phoenix_private.annual_catalog_trim_v1(text) TO supabase_etl_admin"],
  ['MANAGED_INSERT',"GRANT INSERT ON public.central_needs_catalog_years TO supabase_etl_admin"],
  ['MANAGED_WRITE_ALL_DATA',"GRANT pg_write_all_data TO supabase_etl_admin"],
  ['PUBLIC_SELECT',"GRANT SELECT ON public.central_needs_catalog_years TO PUBLIC"],
  ['RLS_DISABLED',"ALTER TABLE public.central_needs_catalog_years DISABLE ROW LEVEL SECURITY"],
  ['RESTRICTIVE_POLICY_REMOVED',"DROP POLICY r1_actor_scope_restrictive ON public.central_needs_catalog_years"],
  ['UNLISTED_ANNUAL_WRITER',"CREATE FUNCTION public.sneaky() RETURNS integer LANGUAGE sql AS $evil$ INSERT INTO public.central_needs_catalog_years(id) VALUES(99) RETURNING id $evil$"],
  ['MANAGED_TRIGGER',"GRANT TRIGGER ON public.central_needs_catalog_years TO supabase_etl_admin"],
  ['MANAGED_SCHEMA_CREATE',"GRANT CREATE ON SCHEMA phoenix_private TO supabase_read_only_user"],
  ['API_OWNS_OBJECT',"CREATE TABLE public.attack(id integer);ALTER TABLE public.attack OWNER TO anon"],
  ['MANAGED_PROFILE_DRIFT',"ALTER ROLE supabase_etl_admin NOLOGIN"],
  ['MANAGED_ADMIN_OPTION_DRIFT',"SET ROLE supabase_admin;GRANT pg_read_all_data TO supabase_etl_admin WITH ADMIN OPTION;RESET ROLE"],
  ['MANAGED_GRANTOR_DRIFT',"SET ROLE supabase_admin;REVOKE pg_read_all_data FROM supabase_etl_admin;RESET ROLE;GRANT pg_read_all_data TO supabase_etl_admin"],
 ];
 for(const [label,setup] of negatives)await check(label,async()=>{
  await sql('BEGIN;'+setup+`;DO $negative$ BEGIN IF NOT EXISTS(SELECT 1 FROM phoenix_private.central_needs_capability_breaches_v1()) THEN RAISE EXCEPTION 'NEGATIVE_WAS_NOT_DETECTED'; END IF;END $negative$;ROLLBACK;`);
  assert.deepEqual(await seals(),[]);assert.deepEqual(await roleFP(),baselineRoles);
 });
 await check('AUTH_RLS_STILL_DENIES_ROWS_WITH_GRANT_TAMPERING',async()=>{const x=await sql('BEGIN;GRANT SELECT ON public.central_needs_catalog_years TO authenticated;SET LOCAL ROLE authenticated;SELECT count(*) FROM public.central_needs_catalog_years;ROLLBACK;');assert.ok(x.out.split('\n').includes('0'));});
 await check('NO_FUNCTION_ACL_OR_DEFINER_ESCALATION',async()=>{const x=(await query("SELECT prosecdef,provolatile::text v,has_function_privilege('anon',oid,'EXECUTE') a,has_function_privilege('authenticated',oid,'EXECUTE') u,has_function_privilege('service_role',oid,'EXECUTE') s FROM pg_proc WHERE oid='phoenix_private.central_needs_capability_breaches_v1()'::regprocedure"))[0];assert.deepEqual(x,{prosecdef:false,v:'s',a:false,u:false,s:false});});
 console.log(JSON.stringify({status:'PASS_P3A1_COMPAT_SEAL_REVIEW',candidate_sha256:patch.sha256,original_sha256:patch.original_sha256,postgres_version:identity.version,system_identifier:identity.id,checks:checks.length,negative_cases:negatives.length,managed_roles_unchanged:true,hosted_connections:0,fixture_scope:'exact P1/P3A1 seal bodies with synthetic catalog-compatible tables and stub RPC signatures; not a full P3A1 application integration replay',remaining_files_9_15:'HOLD_UNCHANGED'}));
 await docker(['exec',name,'touch','/tmp/R33_STOP']);await docker(['wait',name]);await docker(['rm',name]);created=false;console.log('PASS_DISPOSABLE_CONTAINER_REMOVED');
}catch(error){console.error('HOLD_P3A1_COMPAT_'+stage);console.error('DIAGNOSTIC_CODE_'+(error.code||'ASSERT_OR_NATIVE'));process.exitCode=2;}
finally{if(created)await docker(['rm','-f',name]).catch(()=>{});}
