// Only an owner-reviewed, manually dispatched GitHub-hosted Linux runner.
// Hosted connection is read-only. Every SQL candidate is confined to network-none PostgreSQL.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import crypto from 'node:crypto';import {spawn} from 'node:child_process';import {createRequire} from 'node:module';import {fileURLToPath} from 'node:url';
import {authorize,endpoint,identity,quota,TARGET,SYSTEM_IDENTIFIER} from './policy.mjs';
import {verifySourceContract} from './source-contract.mjs';
import {roleReplay} from './restore-roles.mjs';
import {encrypt,decrypt,sha,transferURL} from './recovery-crypto.mjs';import {buildSources} from './verify-preparation.mjs';
import {snapshot,originalProjection,originalData,diagnoseCatalog} from './catalog.mjs';import {isolationFlags,verifyIsolation} from '../chain/runtime-policy.mjs';
const IMAGE='supabase/postgres:17.11.0.003@sha256:7374d196da7e301512cc5329e18040e0f7bb856287b323777cdadecccbc6c7e4';
const e=process.env,here=path.dirname(fileURLToPath(import.meta.url)),MAX=256*1024*1024,owned=[];let source,stage='ENTRY';
async function docker(args,input,limit=MAX,strictWarnings=false){
 return new Promise((resolve,reject)=>{const childEnv=Object.fromEntries(Object.entries(e).filter(([k])=>!k.startsWith('R34_')&&!k.startsWith('ACTIONS_')&&!/TOKEN|PASSWORD|SECRET|PRIVATE_KEY/.test(k)));
  const c=spawn('docker',args,{env:childEnv,stdio:['pipe','pipe','pipe']});const parts=[];let count=0,overflow=false,stderrBytes=0,sqlstate='',stderrTail='';
  c.stdout.on('data',b=>{count+=b.length;if(count>limit){overflow=true;c.kill();}else parts.push(b);});c.stderr.on('data',b=>{stderrBytes+=b.length;stderrTail=(stderrTail+b.toString()).slice(-4096);const m=stderrTail.match(/ERROR:\s+([0-9A-Z]{5})(?::|\s|$)/);if(m)sqlstate=m[1];});c.on('error',()=>reject(Error('NATIVE_START')));c.on('close',code=>{if(code===0&&!overflow&&(!strictWarnings||stderrBytes===0))return resolve(Buffer.concat(parts));if(stage.startsWith('REHEARSAL_')&&args.some(a=>['psql','pg_dump','pg_dumpall','pg_restore'].includes(a)))console.error('R34_SYNTHETIC_SQL_DIAGNOSTIC '+stderrTail.replace(/[a-fA-F0-9]{32,}/g,'REDACTED_HEX').slice(-2048));reject(Error('NATIVE_EXIT_OR_LIMIT'+(sqlstate?'_SQLSTATE_'+sqlstate:'_CODE_'+code+'_OVERFLOW_'+overflow)));});c.stdin.on('error',()=>{});c.stdin.end(input);
 });
}
const name=kind=>'r34-'+kind+'-'+crypto.randomBytes(8).toString('hex');
async function sql(container,statement,db='postgres'){assert.ok(owned.includes(container),'OWNED_ISOLATED_ONLY');return (await docker(['exec','-i',container,'psql','-X','-q','-h','/tmp','-U','supabase_admin','-d',db,'-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate','-At'],statement)).toString();}
function adapter(container){return {query:async(statement,values)=>{assert.ok(!values);return {rows:JSON.parse((await sql(container,"SELECT coalesce(json_agg(r),'[]'::json) FROM ("+statement.replace(/;\s*$/,'')+') r;')).trim())};}};}
async function isolated(){
 const n=name('restore'),ids=(await docker(['run','--rm','--network','none','--read-only','--user','postgres','--entrypoint','/bin/sh',IMAGE,'-c','id -u;id -g'])).toString().trim().split('\n');owned.push(n);
 await docker(['run','-d','--name',n,...isolationFlags(...ids),'--user','postgres','--entrypoint','/bin/bash',IMAGE,'-c',fs.readFileSync(path.join(here,'restore-runtime.sh'),'utf8')]);
 let ready=false;for(let i=0;i<240;i++){try{await docker(['exec',n,'test','-f','/tmp/R34_READY']);ready=true;break;}catch{await new Promise(r=>setTimeout(r,500));}}if(!ready){const state=JSON.parse((await docker(['inspect',n])).toString())[0].State;console.error(JSON.stringify({runtime_status:state.Status,exit_code:state.ExitCode,oom_killed:state.OOMKilled}));const boot=(await docker(['logs',n])).toString();console.error(boot.replace(/[a-fA-F0-9]{32,}/g,'REDACTED_HEX').slice(-4096));try{const log=await docker(['exec',n,'sh','-c','cat /tmp/init.log /tmp/start.log /tmp/server.log 2>/dev/null']);console.error(log.toString().replace(/[a-fA-F0-9]{32,}/g,'REDACTED_HEX').slice(-4096));}catch{}throw Error('RUNTIME_READY');}
 verifyIsolation(JSON.parse((await docker(['inspect',n])).toString())[0],...ids);
 await sql(n,"CREATE SCHEMA vault;CREATE EXTENSION supabase_vault VERSION '0.3.1' SCHEMA vault;DO $v$ DECLARE i uuid;BEGIN IF current_setting('server_version_num')::int<>170011 THEN RAISE EXCEPTION 'VERSION';END IF;i:=vault.create_secret('R34-synthetic','r34-runtime');IF (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id=i)<>'R34-synthetic' THEN RAISE EXCEPTION 'VAULT';END IF;PERFORM vault.update_secret(i,'R34-synthetic-updated');IF (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id=i)<>'R34-synthetic-updated' THEN RAISE EXCEPTION 'VAULT_UPDATE';END IF;END $v$;");
 // The initial database, including this synthetic probe, is replaced by pg_restore --clean --create.
 return n;
}
async function transfer(url,method,body){
 transferURL(url,e.GITHUB_RUN_ID);assert.ok(!body||body.length<=MAX*2,'OBJECT_LIMIT');
 const r=await fetch(url,{method,body,headers:body?{'Content-Type':'application/octet-stream'}:{},redirect:'error',signal:AbortSignal.timeout(120000)});assert.ok(r.ok,'R2_TRANSFER');
 if(method!=='GET')return;const parts=[];let size=0;for await(const b of r.body){size+=b.length;assert.ok(size<=MAX*2,'DOWNLOAD_LIMIT');parts.push(b);}return Buffer.concat(parts);
}
async function storageRows(c){return (await c.query('SELECT bucket_id,name,metadata FROM storage.objects ORDER BY bucket_id,name')).rows;}
async function storageObject(row){
 assert.ok(/^[a-zA-Z0-9_.-]+$/.test(row.bucket_id));assert.ok(row.name.split('/').every(x=>x&&x!=='.'&&x!=='..'));
 const objectPath=row.bucket_id+'/'+row.name.split('/').map(encodeURIComponent).join('/');
 const r=await fetch('https://'+TARGET+'.supabase.co/storage/v1/object/authenticated/'+objectPath,{headers:{apikey:e.R34_STORAGE_READ_KEY,Authorization:'Bearer '+e.R34_STORAGE_READ_KEY},redirect:'error',signal:AbortSignal.timeout(60000)});assert.ok(r.ok,'STORAGE_READ');
 const size=Number(row.metadata?.size);assert.ok(Number.isSafeInteger(size)&&size>=0&&size<=MAX,'STORAGE_SIZE_METADATA');const chunks=[];let actual=0;for await(const b of r.body){actual+=b.length;assert.ok(actual<=size,'STORAGE_SIZE_DRIFT');chunks.push(b);}assert.equal(actual,size);return Buffer.concat(chunks);
}
function externalBundle(text){
 const x=JSON.parse(text);assert.equal(x.target,TARGET);assert.equal(x.owner_verified,true);assert.equal(x.complete,true);
 for(const k of ['auth','storage','platform','key_recovery'])assert.ok(x[k]&&typeof x[k]==='object','EXTERNAL_COVERAGE_'+k);
 assert.ok(Array.isArray(x.coverage)&&['Auth configuration','SMTP and OAuth recovery','JWT signing key recovery','Storage settings and bytes','Vault and encrypted column key recovery','Edge and Realtime configuration'].every(s=>x.coverage.includes(s)),'EXTERNAL_COVERAGE_INCOMPLETE');return x;
}
async function stock(c){
 const values=[];for(const t of ['warehouse_stock','warehouse_stock_movements','outlet_stock','outlet_stock_movements','warehouse_dispatches','warehouse_dispatch_lines','phoenix_movement_events']){
  const q=await c.query(`SELECT count(*)::text AS rows,encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text COLLATE "C"),'[]'::jsonb)::text,'UTF8')),'hex') AS digest FROM public.${t} t`);values.push({table:t,...q.rows[0]});
 }
 values.push({writers:(await c.query("SELECT md5(jsonb_agg(jsonb_build_array(p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proacl::text,p.proconfig) ORDER BY p.oid::regprocedure::text)::text) value FROM pg_proc p WHERE p.proname~*'fefo' OR p.prosrc~*'(insert[[:space:]]+into|update|delete[[:space:]]+from|truncate)[[:space:]]+(public[.])?\"?(warehouse_stock|warehouse_stock_movements|outlet_stock|outlet_stock_movements|warehouse_dispatches|warehouse_dispatch_lines|phoenix_movement_events)\\M'")).rows[0].value});return values;
}
const seals=['phoenix_private.central_needs_capability_breaches_v1()','phoenix_r2.capability_breaches()','phoenix_c4.capability_breaches_v1()','phoenix_monthly.capability_breaches_v1()'];
async function verifySeals(c,complete=false){for(const sig of seals)if((await c.query("SELECT to_regprocedure('"+sig+"') IS NOT NULL present")).rows[0].present)assert.deepEqual((await c.query('SELECT * FROM '+sig)).rows,[],'CAPABILITY_SEAL');else assert.ok(!complete&&sig!==seals[0],'REQUIRED_CAPABILITY_SEAL_MISSING');}
async function negatives(n){
 let passed=0;
 for(const [seal,tamper] of [
  [seals[0],'GRANT SELECT ON public.central_needs_catalog_years TO anon'],
  [seals[0],'GRANT SELECT(planning_year) ON public.central_needs_catalog_years TO authenticated'],
  [seals[0],'ALTER TABLE public.central_needs_catalog_years DISABLE ROW LEVEL SECURITY'],
  [seals[0],'GRANT supabase_read_only_user TO authenticated WITH INHERIT FALSE'],
  [seals[0],'GRANT pg_write_all_data TO supabase_etl_admin'],
  [seals[2],'GRANT pg_maintain TO authenticated WITH INHERIT FALSE'],
  [seals[3],'CREATE ROLE r34_maintain_alias NOLOGIN;GRANT pg_maintain TO r34_maintain_alias WITH INHERIT FALSE'],
  [seals[2],'GRANT SELECT ON phoenix_c4.proofs TO PUBLIC'],
  [seals[3],'GRANT INSERT ON phoenix_monthly.policy_references TO supabase_read_only_user'],
  [seals[3],'ALTER TABLE phoenix_monthly.policy_references DISABLE ROW LEVEL SECURITY']
 ]){await sql(n,'BEGIN;'+tamper+';DO $n$ BEGIN IF NOT EXISTS(SELECT 1 FROM '+seal+") THEN RAISE EXCEPTION 'NEGATIVE_GUARD_MISSED';END IF;END $n$;ROLLBACK;");passed++;}
 return passed;
}
async function recover(){
 authorize(e);assert.equal(process.platform,'linux');assert.equal(e.RUNNER_ENVIRONMENT,'github-hosted');assert.equal(e.RUNNER_OS,'Linux');assert.notEqual(e.RUNNER_DEBUG,'1');assert.notEqual(e.ACTIONS_STEP_DEBUG,'true');assert.notEqual(e.ACTIONS_RUNNER_DEBUG,'true');
 stage='SECURE_CONFIGURATION';for(const k of ['R34_DB_HOST','R34_DB_USER','R34_DB_PASSWORD','R34_DB_CA_PEM','R34_STORAGE_READ_KEY','R34_BACKUP_PUBLIC_KEY_PEM','R34_BACKUP_PRIVATE_KEY_PEM','R34_R2_PUT_URL','R34_R2_GET_URL','R34_QUOTA_RECEIPT_JSON','R34_EXTERNAL_RECOVERY_BUNDLE_JSON'])assert.ok(e[k],'SECURE_INPUT_REQUIRED');
 endpoint(e.R34_DB_HOST,e.R34_DB_USER);quota(JSON.parse(e.R34_QUOTA_RECEIPT_JSON));const ext=externalBundle(e.R34_EXTERNAL_RECOVERY_BUNDLE_JSON);transferURL(e.R34_R2_PUT_URL,e.GITHUB_RUN_ID);transferURL(e.R34_R2_GET_URL,e.GITHUB_RUN_ID);
 const synthetic=Buffer.from('R34 key recovery control');assert.deepEqual(decrypt(encrypt(synthetic,e.R34_BACKUP_PUBLIC_KEY_PEM),e.R34_BACKUP_PRIVATE_KEY_PEM),synthetic);
 const files=buildSources(path.resolve('app'));stage='PINNED_RESTORE_RUNTIME';await docker(['pull',IMAGE]);const image=JSON.parse((await docker(['image','inspect',IMAGE])).toString())[0];assert.ok(image.RepoDigests.some(x=>x.endsWith('@'+IMAGE.split('@')[1])));const restored=await isolated();
 stage='PRODUCTION_READONLY_SNAPSHOT';const pg=createRequire(path.resolve('app/package.json'))('pg');source=new pg.Client({host:e.R34_DB_HOST,user:e.R34_DB_USER,password:e.R34_DB_PASSWORD,port:5432,database:'postgres',ssl:{rejectUnauthorized:true,ca:e.R34_DB_CA_PEM},connectionTimeoutMillis:12000,options:'-c default_transaction_read_only=on -c statement_timeout=120000 -c lock_timeout=1000'});await source.connect();await source.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 const id=(await source.query("SELECT current_database() database,current_setting('server_version_num')::int server_version_num,(SELECT system_identifier::text FROM pg_control_system()) system_identifier")).rows[0];identity({...id,ssl_verify_full:source.connection.stream.authorized===true});assert.equal((await source.query('SELECT rolname FROM pg_roles WHERE oid=10')).rows[0].rolname,'supabase_admin','BOOTSTRAP_ROLE_DRIFT');const provider=(await source.query("SELECT current_setting('supautils.privileged_role',true) role,current_setting('supautils.privileged_extensions_superuser',true) superuser,current_setting('supautils.privileged_extensions',true) extensions")).rows[0];assert.equal(provider.role,'supabase_privileged_role');assert.equal(provider.superuser,'supabase_admin');for(const name of ['pg_stat_statements','pgcrypto','uuid-ossp','pg_trgm','supabase_vault'])assert.ok(provider.extensions.split(',').map(x=>x.trim()).includes(name),'PROVIDER_EXTENSION_CONTRACT_DRIFT');await verifySourceContract(source);await verifySeals(source);
 assert.equal((await source.query('SELECT count(*)::int n FROM vault.secrets')).rows[0].n,0,'VAULT_CONTENT_DRIFT_REQUIRES_REAL_ROOT_KEY_REHEARSAL');
 assert.ok(Number((await source.query("SELECT pg_database_size(current_database())::text n")).rows[0].n)<=128*1024*1024,'REQUALIFY_DATABASE_GROWTH_AND_FREE_EGRESS');
 assert.equal((await source.query("SELECT count(*)::int n FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')")).rows[0].n,0,'NONDEFAULT_TABLESPACE_REQUIRES_QUALIFICATION');
 const before=await snapshot(source),stockBefore=await stock(source),objects=await storageRows(source),snap=(await source.query('SELECT pg_export_snapshot() id')).rows[0].id;assert.match(snap,/^[0-9A-F-]+$/i);
 const client=name('source-client');owned.push(client);await docker(['run','-d','--name',client,'--network','bridge','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=64m','--user','postgres','--entrypoint','/bin/sh',IMAGE,'-c','sleep 1800']);
 assert.ok(!/[\r\n]/.test(e.R34_DB_PASSWORD));const escape=s=>s.replaceAll('\\','\\\\').replaceAll(':','\\:');
 await docker(['exec','-i',client,'sh','-c','umask 077; cat > /tmp/r34.pgpass'],[e.R34_DB_HOST,'5432','postgres',e.R34_DB_USER,e.R34_DB_PASSWORD].map(escape).join(':')+'\n');await docker(['exec','-i',client,'sh','-c','umask 077; cat > /tmp/r34-ca.pem'],e.R34_DB_CA_PEM);
 const connection=['--env','PGHOST='+e.R34_DB_HOST,'--env','PGPORT=5432','--env','PGDATABASE=postgres','--env','PGUSER='+e.R34_DB_USER,'--env','PGPASSFILE=/tmp/r34.pgpass','--env','PGSSLMODE=verify-full','--env','PGSSLROOTCERT=/tmp/r34-ca.pem','--env','PGCONNECT_TIMEOUT=12','--env','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=120000 -c lock_timeout=1000'];
 stage='COMPLETE_ROLE_BACKUP';const roles=await docker(['exec',...connection,client,'pg_dumpall','--no-password','--database=postgres','--roles-only'],undefined,16*1024*1024,true);
 stage='CONSISTENT_DATABASE_BACKUP';const dump=await docker(['exec',...connection,client,'pg_dump','--no-password','--format=custom','--create','--snapshot='+snap],undefined,MAX,true);
 const stored=[];let storageSize=0;for(const row of objects){const bytes=await storageObject(row);storageSize+=bytes.length;assert.ok(storageSize<=MAX/2,'STORAGE_TOTAL_LIMIT');stored.push({...row,sha256:sha(bytes),bytes:bytes.toString('base64')});}
 // A second read verifies each stored object remained unchanged during capture.
 for(const row of stored)assert.equal(sha(await storageObject(row)),row.sha256,'STORAGE_CHANGED_DURING_CAPTURE');assert.deepEqual(await snapshot(source),before,'SOURCE_SEQUENCE_OR_CATALOG_DRIFT');
 await source.query('COMMIT');await source.end();source=null;await docker(['rm','-f',client]);owned.splice(owned.indexOf(client),1);
 const plain=Buffer.from(JSON.stringify({format:'R34_FULL_LOGICAL_DATABASE_STORAGE_EXTERNAL_V1',target:TARGET,identity:id,captured_at:new Date().toISOString(),before,stockBefore,external_recovery:ext,storage:stored,roles:roles.toString('base64'),dump:dump.toString('base64')}));assert.ok(plain.length<=MAX,'ARCHIVE_LIMIT');
 stage='ENCRYPTED_INDEPENDENT_BACKUP';const encrypted=encrypt(plain,e.R34_BACKUP_PUBLIC_KEY_PEM);await transfer(e.R34_R2_PUT_URL,'PUT',encrypted);const downloaded=await transfer(e.R34_R2_GET_URL,'GET');assert.equal(sha(downloaded),sha(encrypted));const recovered=decrypt(downloaded,e.R34_BACKUP_PRIVATE_KEY_PEM);assert.equal(sha(recovered),sha(plain));const archive=JSON.parse(recovered);assert.equal(archive.identity.system_identifier,SYSTEM_IDENTIFIER);console.log(JSON.stringify({event:'R34_ENCRYPTED_BACKUP_DOWNLOADED_VERIFIED',target:TARGET,run_id:e.GITHUB_RUN_ID,sha256:sha(encrypted),bytes:encrypted.length,restore_pass:false}));
 stage='EXACT_DATABASE_RESTORE';await sql(restored,roleReplay(Buffer.from(archive.roles,'base64')));await docker(['exec','-i',restored,'pg_restore','-h','/tmp','-U','supabase_admin','-d','template1','--clean','--if-exists','--create','--use-set-session-authorization','--exit-on-error'],Buffer.from(archive.dump,'base64'));
 const c=adapter(restored);assert.notEqual((await c.query('SELECT system_identifier::text id FROM pg_control_system()')).rows[0].id,SYSTEM_IDENTIFIER);assert.deepEqual(await snapshot(c),archive.before,'RESTORE_DATA_SCHEMA_ROLES_ACL_RLS_MISMATCH');const projection=await originalProjection(c);
 for(const object of archive.storage)assert.equal(sha(Buffer.from(object.bytes,'base64')),object.sha256);assert.deepEqual(await stock(c),archive.stockBefore);stage='RESTORED_DATABASE_CHAIN';const applied=[];
 for(const f of files){assert.equal(sha(f.bytes),f.sha256);await sql(restored,Buffer.concat([Buffer.from('SET SESSION AUTHORIZATION postgres;\n'),f.bytes]));await verifySeals(c);assert.deepEqual(await stock(c),stockBefore,'STOCK_OR_FEFO_DRIFT');const now=await snapshot(c);assert.deepEqual(now.catalog.roles,before.catalog.roles,'ROLE_TRAITS_DRIFT');assert.deepEqual(now.catalog.memberships,before.catalog.memberships,'ROLE_GRAPH_DRIFT');assert.deepEqual(await originalData(c,projection),projection,'ORIGINAL_TABLE_DATA_DRIFT');applied.push({order:f.order,sha256:f.sha256,status:'PASS'});}
 stage='RESTORED_NEGATIVE_GUARDS';const count=await negatives(restored);await verifySeals(c,true);assert.deepEqual(await stock(c),stockBefore);
 console.log(JSON.stringify({status:'PASS_FULL_BACKUP_RESTORE_AND_SQL_CHAIN',target:TARGET,source_system_identifier:SYSTEM_IDENTIFIER,image:IMAGE,encrypted_backup_sha256:sha(encrypted),independent_download_decrypt_restore:true,table_comparisons:before.data.length,storage_objects_verified:stored.length,negative_guard_checks:count,files:applied,production_sql_applied:0,migration_execution_principal:'postgres',real_auth_postgrest_service_acceptance:'NOT_RUN',external_configuration_coverage:'OWNER_VERIFIED_BUNDLE_PRESERVED_NOT_INDEPENDENTLY_REBUILT'}));
 for(const b of [roles,dump,plain,recovered])b.fill(0);
}
async function cleanup(){await source?.end().catch(()=>{});for(const n of owned){try{await docker(['rm','-f',n]);}catch{console.error('HOLD_R34_OWNED_CONTAINER_CLEANUP');process.exitCode=2;}}}
export async function rehearsal(){
 try{
  assert.equal(process.platform,'linux');assert.equal(e.RUNNER_ENVIRONMENT,'github-hosted');authorize(e);
  for(const k of Object.keys(e))assert.ok(!/R34_(DB_|STORAGE_|BACKUP_|R2_|EXTERNAL_)/.test(k),'REHEARSAL_HAS_NO_PRODUCTION_INPUT');
  stage='REHEARSAL_IMAGE_AND_SOURCE_VAULT';await docker(['pull',IMAGE]);const a=await isolated();
  await sql(a,"CREATE ROLE postgres NOSUPERUSER LOGIN CREATEDB CREATEROLE BYPASSRLS;CREATE ROLE supabase_privileged_role NOLOGIN;GRANT supabase_privileged_role TO postgres;CREATE SCHEMA extensions AUTHORIZATION postgres;ALTER DATABASE postgres OWNER TO postgres;SET SESSION AUTHORIZATION postgres;CREATE EXTENSION pg_stat_statements SCHEMA extensions;CREATE EXTENSION pgcrypto SCHEMA extensions;CREATE EXTENSION \"uuid-ossp\" SCHEMA extensions;RESET SESSION AUTHORIZATION;CREATE EXTENSION pg_trgm SCHEMA extensions;CREATE ROLE r34_synthetic_reader NOLOGIN;CREATE SCHEMA r34_synthetic;CREATE TABLE r34_synthetic.items(id int PRIMARY KEY,qty int);INSERT INTO r34_synthetic.items VALUES(1,1200);ALTER TABLE r34_synthetic.items ENABLE ROW LEVEL SECURITY;GRANT USAGE ON SCHEMA r34_synthetic TO r34_synthetic_reader;GRANT SELECT ON r34_synthetic.items TO r34_synthetic_reader;CREATE POLICY synthetic_read ON r34_synthetic.items FOR SELECT TO r34_synthetic_reader USING(id=1);CREATE FUNCTION r34_synthetic.identity_qty(v int) RETURNS int LANGUAGE sql IMMUTABLE AS 'SELECT v';CREATE TYPE r34_synthetic.unit AS ENUM('box','test');");
  stage='REHEARSAL_SOURCE_CATALOG';let before;try{before=await snapshot(adapter(a));}catch(error){await diagnoseCatalog(adapter(a));throw error;}
  stage='REHEARSAL_ORIGINAL_PROJECTION';const projection=await originalProjection(adapter(a));
  stage='REHEARSAL_DATABASE_ARCHIVE';const dump=await docker(['exec',a,'pg_dump','-h','/tmp','-U','supabase_admin','-d','postgres','-Fc','--create']);
  stage='REHEARSAL_ROLE_ARCHIVE';const roles=await docker(['exec',a,'pg_dumpall','-h','/tmp','-U','supabase_admin','--database=postgres','--roles-only']);
  // A separate provider-aligned bootstrap restores the original role dump.
  stage='REHEARSAL_TARGET_AND_KEY_RECOVERY';const b=await isolated();
  const syntheticRoot=await docker(['exec',a,'cat','/etc/postgresql-custom/pgsodium_root.key']);
  try{
   await docker(['exec',b,'pg_ctl','-D','/tmp/r34-data','-m','fast','-w','stop']);
   await docker(['exec','-i',b,'sh','-c','umask 077; cat > /etc/postgresql-custom/pgsodium_root.key'],syntheticRoot);
   await docker(['exec',b,'pg_ctl','-D','/tmp/r34-data','-l','/tmp/server.log','-w','start']);
  }finally{syntheticRoot.fill(0);}
  await sql(b,roleReplay(roles));
  stage='REHEARSAL_ARCHIVE_RESTORE';await docker(['exec','-i',b,'pg_restore','-h','/tmp','-U','supabase_admin','-d','template1','--clean','--if-exists','--create','--use-set-session-authorization','--exit-on-error'],dump);
  stage='REHEARSAL_CATALOG_COMPARISON';assert.deepEqual(await snapshot(adapter(b)),before,'SYNTHETIC_FULL_RESTORE_MISMATCH');
  stage='REHEARSAL_RESTORED_VAULT_DECRYPT';assert.equal((await sql(b,"SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name='r34-runtime'" )).trim(),'R34-synthetic-updated','RESTORED_VAULT_DECRYPT');
  stage='REHEARSAL_ORIGINAL_DATA_GUARD';await sql(b,'ALTER TABLE r34_synthetic.items ADD COLUMN extra text;');assert.deepEqual(await originalData(adapter(b),projection),projection);
  await sql(b,'UPDATE r34_synthetic.items SET qty=1201;');assert.notDeepEqual(await originalData(adapter(b),projection),projection,'DATA_DRIFT_MISSED');
  console.log('PASS_R34_SYNTHETIC_RESTORE_CATALOG_RLS_ACL_VAULT_NO_PRODUCTION_ACCESS');
 }catch(error){const code=/^NATIVE_EXIT_OR_LIMIT(?:_SQLSTATE_[0-9A-Z]{5}|_CODE_-?[0-9]+_OVERFLOW_(?:true|false))?$/.test(error.message)?'_'+error.message:'_'+(error instanceof TypeError?'TYPE_ERROR':error instanceof SyntaxError?'JSON_SYNTAX_ERROR':'ASSERTION_OR_RUNTIME_ERROR');console.error('HOLD_R34_'+stage+code);for(const frame of String(error.stack).split('\n').slice(1,5))if(/^\s+at .*file:\/\/.+\.mjs:[0-9]+:[0-9]+\)?$/.test(frame))console.error(frame);process.exitCode=2;}finally{await cleanup();}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{await recover();}catch(error){const code=/^NATIVE_EXIT_OR_LIMIT_SQLSTATE_[0-9A-Z]{5}$/.test(error.message)?'_'+error.message:'';console.error('HOLD_R34_'+stage+code);process.exitCode=2;}finally{await cleanup();}
}
