import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
export const ORIGINAL_SHA256='1cfab7101634410288702e71bde670d6816ceeaea1dd06a21f510f9cc86e90bf';
export const sha=b=>createHash('sha256').update(b).digest('hex');
const anchor="  -- (a) no non-root write, TRUNCATE, REFERENCES, TRIGGER or MAINTAIN on any";
const oldRead="   WHERE u.oid<>c.relowner AND (pg_catalog.has_table_privilege(u.oid,c.oid,'SELECT')\n     OR pg_catalog.has_any_column_privilege(u.oid,c.oid,'SELECT'))";
export const providerCTE=`,\n  -- R33 compatibility: exact measured infrastructure readers, not API roles.
  -- Existing pg_read_all_data capability is recognized; no ACL or role changes.
  managed_readers AS (
    SELECT u.oid
      FROM nonroot u JOIN pg_catalog.pg_roles r ON r.oid=u.oid
      JOIN pg_catalog.pg_auth_members edge ON edge.member=r.oid
      JOIN pg_catalog.pg_roles parent ON parent.oid=edge.roleid AND parent.rolname='pg_read_all_data'
      JOIN pg_catalog.pg_roles grantor ON grantor.oid=edge.grantor AND grantor.rolname='supabase_admin'
     WHERE r.rolname IN ('supabase_etl_admin','supabase_read_only_user')
       AND r.rolcanlogin AND r.rolinherit AND r.rolbypassrls
       AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb
       AND r.rolreplication=(r.rolname='supabase_etl_admin')
       AND r.rolconnlimit=-1
       AND r.rolconfig IS NOT DISTINCT FROM CASE WHEN r.rolname='supabase_read_only_user'
         THEN ARRAY['default_transaction_read_only=on']::text[] ELSE NULL::text[] END
       AND NOT edge.admin_option AND edge.inherit_option AND edge.set_option
       AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members extra
         WHERE extra.member=r.oid AND extra.roleid=parent.oid AND extra.grantor<>edge.grantor)
       AND pg_catalog.pg_has_role(r.oid,'pg_read_all_data','USAGE')
       AND NOT pg_catalog.pg_has_role(r.oid,'pg_write_all_data','MEMBER')
       AND NOT EXISTS (SELECT 1 FROM (VALUES ('anon'),('authenticated'),('service_role')) api(name)
         WHERE pg_catalog.pg_has_role(api.name::name,r.oid,'MEMBER'))
       AND NOT EXISTS (SELECT 1 FROM acl_manifest m
         WHERE pg_catalog.to_regprocedure(m.sig) IS NOT NULL
           AND pg_catalog.has_function_privilege(r.oid,pg_catalog.to_regprocedure(m.sig),'EXECUTE'))
  )\n`;
export const extraRead=`
      -- Exempt only inherited platform-wide SELECT. Explicit/inherited app ACL
      -- grants (including column SELECT and PUBLIC) remain a seal breach.
      AND NOT EXISTS (
        SELECT 1 FROM managed_readers managed WHERE managed.oid=u.oid
          AND NOT EXISTS (
            SELECT 1 FROM (
              SELECT acl.grantee FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) acl
               WHERE acl.privilege_type='SELECT'
              UNION ALL
              SELECT acl.grantee FROM pg_catalog.pg_attribute att
                CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(att.attacl,ARRAY[]::aclitem[])) acl
               WHERE att.attrelid=c.oid AND att.attnum>0 AND NOT att.attisdropped AND acl.privilege_type='SELECT'
            ) app_acl
            WHERE CASE WHEN app_acl.grantee=0 THEN true
              ELSE pg_catalog.pg_has_role(u.oid,app_acl.grantee,'USAGE') END
          )
      )`;
export function patchP3A1(bytes){
 assert.equal(sha(bytes),ORIGINAL_SHA256,'ORIGINAL_P3A1_SOURCE_DRIFT');
 const source=Buffer.from(bytes).toString('utf8');
 assert.equal(source.split(anchor).length,2);assert.equal(source.split(oldRead).length,2);
 let patched=source.replace(anchor,providerCTE+anchor).replace(oldRead,oldRead+extraRead);
 // Round-trip proves every other byte, including business, RLS and prechecks.
 assert.equal(patched.replace(providerCTE,'').replace(extraRead,''),source);
 return {sql:patched,sha256:sha(Buffer.from(patched)),original_sha256:ORIGINAL_SHA256};
}
export function extractSeal(sql){
 const start=sql.indexOf('CREATE OR REPLACE FUNCTION phoenix_private.central_needs_capability_breaches_v1()');
 assert.ok(start>=0);const end=sql.indexOf('\n$$;',start);assert.ok(end>start);return sql.slice(start,end+4);
}
