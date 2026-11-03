import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {patchP3A1,extractSeal,providerCTE,extraRead,ORIGINAL_SHA256,sha} from './p3a1-compat-patch.mjs';
const file=process.env.R33_ORIGINAL_P3A1_SOURCE;
const original=fs.readFileSync(file);
test('source drift fails closed and original hash is fixed',()=>{assert.equal(sha(original),ORIGINAL_SHA256);assert.throws(()=>patchP3A1(Buffer.concat([original,Buffer.from('\n')])));});
test('only the two catalog-read fragments change; all business, RLS and prechecks retain exact bytes',()=>{
 const candidate=patchP3A1(original);assert.equal(candidate.sql.replace(providerCTE,'').replace(extraRead,''),original.toString());
 assert.equal(extractSeal(candidate.sql).replace(providerCTE,'').replace(extraRead,''),extractSeal(original.toString()));
});
test('compatibility has no role/ACL mutation, no general name-only exclusion and no API exception',()=>{
 const added=providerCTE+extraRead;
 assert.ok(!/\b(?:ALTER\s+ROLE|GRANT\s+\w+\s+TO|REVOKE\s+\w+\s+FROM|SECURITY\s+DEFINER)\b/i.test(added));
 for(const required of ["grantor.rolname='supabase_admin'","NOT edge.admin_option","edge.inherit_option","edge.set_option","('anon'),('authenticated'),('service_role')","att.attacl","c.relacl","has_function_privilege"])assert.ok(added.includes(required));
});
test('NULL/empty ACLs are not turned into zero-dimensional arrays for aclexplode',()=>{
 assert.ok(!extraRead.includes('ARRAY[]::aclitem[]'));
 assert.ok(extraRead.includes('cardinality(att.attacl)>0'));
 assert.ok(extraRead.includes('cardinality(c.relacl)>0'));
 assert.ok(extraRead.includes("acldefault('r',c.relowner)"));
});
