import assert from 'node:assert/strict';
export const KEY_DIR='/etc/postgresql-custom';
export const KEY_PATH=KEY_DIR+'/pgsodium_root.key';
function id(value){assert.match(value,/^[1-9][0-9]{0,4}$/);assert.ok(Number(value)<=65535);return value;}
export function isolationFlags(uid,gid){
 id(uid);id(gid);
 return ['--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=512m','--tmpfs',KEY_DIR+':rw,nosuid,nodev,noexec,size=1m,mode=0700,uid='+uid+',gid='+gid];
}
export function verifyIsolation(inspect,uid,gid){
 const flags=isolationFlags(uid,gid),h=inspect.HostConfig;
 assert.equal(h.NetworkMode,'none');assert.equal(h.ReadonlyRootfs,true);
 assert.equal(Object.keys(h.PortBindings||{}).length,0);
 assert.deepEqual(Object.keys(h.Tmpfs).sort(),[KEY_DIR,'/tmp'].sort());
 const specs=flags.filter((_,i)=>i>0&&flags[i-1]==='--tmpfs');
 for(const spec of specs){
  const i=spec.indexOf(':'),dest=spec.slice(0,i),expected=spec.slice(i+1).split(',').sort();
  assert.deepEqual(h.Tmpfs[dest].split(',').sort(),expected);
 }
 assert.ok(inspect.Mounts.every(m=>m.Type==='tmpfs'&&[KEY_DIR,'/tmp'].includes(m.Destination)));
}
export function parseKeyContract(text){
 const lines=text.trim().split('\n');assert.equal(lines.length,3);
 assert.equal(lines[0],KEY_PATH);assert.ok(lines[1].startsWith('/')&&!/[\r\0]/.test(lines[1]));assert.match(lines[2],/^[a-f0-9]{64}$/);
 return {key_file_path:lines[0],key_helper_path:lines[1],key_helper_sha256:lines[2],synthetic_key_contract_verified:true,key_material_logged:false};
}
