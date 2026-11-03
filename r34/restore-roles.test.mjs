import {test} from 'node:test';import assert from 'node:assert/strict';import {roleReplay} from './restore-roles.mjs';
test('bootstrap replay preserves every attribute, credential and other role statement',()=>{
 const source=Buffer.from('CREATE ROLE supabase_admin;\nALTER ROLE supabase_admin WITH SUPERUSER LOGIN PASSWORD NULL;\nCREATE ROLE postgres;\nALTER ROLE postgres WITH NOSUPERUSER;\nGRANT postgres TO supabase_admin;\n');
 const replay=roleReplay(source).toString();assert.ok(replay.endsWith(source.toString().split('\n').slice(1).join('\n')));assert.equal(source.toString().startsWith('CREATE ROLE supabase_admin;'),true);
 for(const invalid of ['',source.toString().replace('SUPERUSER','NOSUPERUSER'),source.toString()+'CREATE ROLE supabase_admin;\n'])assert.throws(()=>roleReplay(Buffer.from(invalid)));
});
