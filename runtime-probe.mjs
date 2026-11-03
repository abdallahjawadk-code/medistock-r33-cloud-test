import fs from 'node:fs';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const IMAGE='supabase/postgres:17.11.0.003@sha256:7374d196da7e301512cc5329e18040e0f7bb856287b323777cdadecccbc6c7e4';
const e=process.env;
const root=path.dirname(fileURLToPath(import.meta.url));
const container='r33-runtime-'+e.GITHUB_RUN_ID+'-'+e.GITHUB_RUN_ATTEMPT;
let created=false,stage='AUTHORIZATION';
async function docker(args,input){
 return new Promise((resolve,reject)=>{
  const p=spawn('docker',args,{stdio:['pipe','pipe','pipe']});const chunks=[];let count=0,overflow=false;
  p.stdout.on('data',b=>{count+=b.length;if(count>1024*1024){overflow=true;p.kill();}else chunks.push(b);});
  // Never print native stderr or server configuration/key material.
  p.stderr.resume();p.on('error',()=>reject(Error('PROCESS_START')));
  p.on('close',code=>code===0&&!overflow?resolve(Buffer.concat(chunks)):reject(Error('PROCESS_FAILED')));
  p.stdin.on('error',()=>{});p.stdin.end(input);
 });
}
try{
 assert.equal(e.GITHUB_REPOSITORY,'abdallahjawadk-code/medistock-r33-cloud-test');
 assert.equal(e.GITHUB_REPOSITORY_OWNER,'abdallahjawadk-code');
 assert.equal(e.GITHUB_ACTOR,'abdallahjawadk-code');
 assert.equal(e.GITHUB_EVENT_NAME,'workflow_dispatch');
 assert.equal(e.GITHUB_REF,'refs/heads/master');
 assert.match(e.R33_APPROVED_TOOLS_SHA||'',/^[a-f0-9]{40}$/);
 assert.equal(e.R33_APPROVED_TOOLS_SHA,e.GITHUB_SHA);
 assert.equal(e.GITHUB_ACTIONS,'true');assert.equal(e.RUNNER_ENVIRONMENT,'github-hosted');
 assert.equal(e.RUNNER_OS,'Linux');assert.equal(process.platform,'linux');
 assert.ok(e.RUNNER_DEBUG!=='1'&&e.ACTIONS_RUNNER_DEBUG!=='true'&&e.ACTIONS_STEP_DEBUG!=='true');
 assert.match(container,/^r33-runtime-[0-9]+-[0-9]+$/);
 stage='LINUX_ENGINE';
 const info=JSON.parse((await docker(['info','--format','{{json .}}'])).toString());assert.equal(info.OSType,'linux');
 stage='PINNED_IMAGE';await docker(['pull',IMAGE]);
 const image=JSON.parse((await docker(['image','inspect',IMAGE])).toString())[0];
 assert.equal(image.Os,'linux');assert.equal(image.Architecture,'amd64');
 assert.ok(image.RepoDigests.some(x=>x.endsWith('@'+IMAGE.split('@')[1])));
 stage='ISOLATED_POSTGRES_START';
 await docker(['run','-d','--name',container,'--label','medistock.scope=r33-runtime-phase1','--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,size=512m','--user','postgres','--entrypoint','/bin/bash',IMAGE,'-c',fs.readFileSync(path.join(root,'cloud-runtime.sh'),'utf8')]);created=true;
 // Bounded readiness polling only, never retries SQL or a failed probe.
 let ready=false;
 for(let i=0;i<60;i++){
  try{await docker(['exec',container,'test','-f','/tmp/R33_READY']);ready=true;break;}
  catch{const state=JSON.parse((await docker(['inspect','--format','{{json .State}}',container])).toString());if(!state.Running)throw Error('STARTUP_STOPPED');await new Promise(r=>setTimeout(r,500));}
 }
 assert.ok(ready);
 const inspect=JSON.parse((await docker(['inspect',container])).toString())[0];
 assert.equal(inspect.HostConfig.NetworkMode,'none');assert.equal(inspect.HostConfig.ReadonlyRootfs,true);
 assert.equal(inspect.Config.Image,IMAGE);assert.deepEqual(inspect.HostConfig.PortBindings,{});
 assert.ok(inspect.Mounts.every(m=>m.Type==='tmpfs'));
 stage='VAULT_CREATE_AND_CRYPTO_ROUNDTRIP';
 const sql=`CREATE SCHEMA vault;
CREATE EXTENSION supabase_vault VERSION '0.3.1' SCHEMA vault;
DO $r33$ DECLARE v_id uuid; BEGIN
 IF current_setting('server_version_num')::int<>170011 THEN RAISE EXCEPTION 'POSTGRES_VERSION'; END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_extension WHERE extname='supabase_vault' AND extversion='0.3.1') THEN RAISE EXCEPTION 'VAULT_VERSION'; END IF;
 v_id:=vault.create_secret('R33-SYNTHETIC-ROUNDTRIP','r33-runtime-only','synthetic disposable data');
 IF NOT EXISTS(SELECT 1 FROM vault.decrypted_secrets s WHERE s.id=v_id AND s.decrypted_secret='R33-SYNTHETIC-ROUNDTRIP') THEN RAISE EXCEPTION 'VAULT_ROUNDTRIP'; END IF;
 PERFORM vault.update_secret(v_id,'R33-SYNTHETIC-UPDATED');
 IF NOT EXISTS(SELECT 1 FROM vault.decrypted_secrets s WHERE s.id=v_id AND s.decrypted_secret='R33-SYNTHETIC-UPDATED') THEN RAISE EXCEPTION 'VAULT_UPDATE_ROUNDTRIP'; END IF;
END $r33$;
SELECT json_build_object('postgres_version',current_setting('server_version'),'vault_version',(SELECT extversion FROM pg_extension WHERE extname='supabase_vault'),'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'create_decrypt_roundtrip',true,'update_decrypt_roundtrip',true);`;
 const raw=(await docker(['exec','-i',container,'psql','-X','-h','/tmp','-U','r33_isolated_restore','-d','postgres','-v','ON_ERROR_STOP=1','-At'],sql)).toString();
 const proof=JSON.parse(raw.trim().split('\n').at(-1));
 assert.equal(proof.postgres_version,'17.11');assert.equal(proof.vault_version,'0.3.1');
 assert.notEqual(proof.system_identifier,'7692131729119822239');
 console.log(JSON.stringify({status:'PASS_RUNTIME_PROBE',commit:e.GITHUB_SHA,image:IMAGE,image_id:image.Id,network:'none',read_only_root:true,published_ports:0,persistent_volumes:0,hosted_connections:0,...proof}));
 stage='GRACEFUL_STOP';await docker(['exec',container,'touch','/tmp/R33_STOP']);await docker(['wait',container]);
 await docker(['rm',container]);created=false;
 console.log('PASS_DISPOSABLE_CONTAINER_REMOVED');
}catch{console.error('HOLD_RUNTIME_PROBE_'+stage);process.exitCode=2;}
finally{
 if(created){try{await docker(['rm','-f',container]);console.log('DISPOSABLE_CLEANUP_COMPLETED');}catch{console.error('HOLD_DISPOSABLE_CLEANUP');process.exitCode=2;}}
}
