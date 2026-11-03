import test from 'node:test';
import assert from 'node:assert/strict';
import {KEY_DIR,KEY_PATH,isolationFlags,verifyIsolation,parseKeyContract} from './runtime-policy.mjs';
test('bounded key tmpfs uses the pinned image postgres UID and GID',()=>{
 const flags=isolationFlags('101','102');
 assert.ok(flags.includes(KEY_DIR+':rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=101,gid=102'));
 assert.ok(flags.includes('--read-only'));assert.equal(flags[flags.indexOf('--network')+1],'none');
 for(const ids of [['0','102'],['101','0'],['101;echo','102'],['-1','102'],['101','999999']])assert.throws(()=>isolationFlags(...ids));
});
const good=()=>({HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,PortBindings:null,Tmpfs:{'/tmp':'rw,nosuid,nodev,noexec,size=512m', [KEY_DIR]:'rw,nosuid,nodev,noexec,size=1m,mode=0700,uid=101,gid=102'}},Mounts:[{Type:'tmpfs',Destination:'/tmp'},{Type:'tmpfs',Destination:KEY_DIR}]});
test('accepts only the two bounded transient mounts, without ports or writable root',()=>{
 assert.doesNotThrow(()=>verifyIsolation(good(),'101','102'));
 for(const mutate of [x=>{x.HostConfig.ReadonlyRootfs=false},x=>{x.HostConfig.NetworkMode='bridge'},x=>{x.HostConfig.PortBindings={'5432/tcp':[{HostPort:'5432'}]}},x=>{x.Mounts.push({Type:'volume',Destination:'/data'})},x=>{x.HostConfig.Tmpfs[KEY_DIR]='rw,size=1g'},x=>{x.HostConfig.Tmpfs['/other']='rw,size=1m'}]){
  const x=good();mutate(x);assert.throws(()=>verifyIsolation(x,'101','102'));
 }
});
test('requires noexec and owner-only key directory, not just a tmpfs label',()=>{
 for(const remove of ['noexec','nodev','nosuid','mode=0700','uid=101']){
  const x=good();x.HostConfig.Tmpfs[KEY_DIR]=x.HostConfig.Tmpfs[KEY_DIR].split(',').filter(y=>y!==remove).join(',');assert.throws(()=>verifyIsolation(x,'101','102'));
 }
});
test('actual-image contract report accepts the canonical key path and code hash only',()=>{
 const report=KEY_PATH+'\n/usr/lib/postgresql/bin/pgsodium_getkey.sh\n'+'a'.repeat(64)+'\n';
 assert.equal(parseKeyContract(report).key_file_path,KEY_PATH);
 assert.throws(()=>parseKeyContract(report.replace(KEY_PATH,'/tmp/vault-root.key')));
 assert.throws(()=>parseKeyContract(report.replace('a'.repeat(64),'not-a-digest')));
 assert.throws(()=>parseKeyContract(report+'extra-material\n'));
});
