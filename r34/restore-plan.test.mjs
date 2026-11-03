import {test} from 'node:test';import assert from 'node:assert/strict';import {restorePlan} from './restore-plan.mjs';
test('native TOC is covered exactly once including database ACL/properties and extension data',()=>{
 const toc='; synthetic\n; TOC Entries: 6\n1; 1262 10 DATABASE - postgres postgres\n2; 2615 20 SCHEMA - vault supabase_admin\n3; 3079 21 EXTENSION - supabase_vault \n4; 0 22 TABLE DATA vault secrets supabase_admin\n5; 0 10 DATABASE PROPERTIES - postgres postgres\n6; 0 10 ACL - DATABASE postgres postgres\n';
 const ext=[['plpgsql','1.0','pg_catalog','supabase_admin'],['supabase_vault','0.3.1','vault','supabase_admin']],plan=restorePlan(toc,ext);
 assert.equal(plan.total,6);assert.equal(plan.initial_entries,4);assert.equal(plan.extension_entries,1);assert.equal(plan.remaining_entries,1);assert.match(plan.remaining,/TABLE DATA vault secrets/);assert.match(plan.initial,/DATABASE PROPERTIES/);assert.match(plan.initial,/ACL - DATABASE/);
 for(const bad of [toc.replace('1; 1262 10 DATABASE - postgres postgres\n',''),toc+'1; 0 0 TABLE public duplicate postgres\n',toc.replace('supabase_vault ','unrecorded '),toc.replace('2; 2615 20 SCHEMA - vault supabase_admin\n','')])assert.throws(()=>restorePlan(bad,ext));
});
