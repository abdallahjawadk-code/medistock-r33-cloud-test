import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {providerCTE,extraRead,extractSeal,sha} from './p3a1-compat-patch.mjs';

export const ACCEPTED_A1='fecadd2f8c3cf2bb536392421aa1cb0f9ad4db69eafbaecf94a2c1e72ec8a989';
const anchor='  -- (a) no non-root write, TRUNCATE, REFERENCES, TRIGGER or MAINTAIN on any';
const read="   WHERE u.oid<>c.relowner AND (pg_catalog.has_table_privilege(u.oid,c.oid,'SELECT')\n     OR pg_catalog.has_any_column_privilege(u.oid,c.oid,'SELECT'))";
export function bodyMD5(sql){
 const seal=extractSeal(sql),body=seal.match(/AS \$\$([\s\S]*)\$\$;/)?.[1];
 assert.ok(body,'SEAL_BODY_REQUIRED');return createHash('md5').update(body).digest('hex');
}
function change(sql,oldText,newText,changes,reason){
 assert.equal(sql.split(oldText).length,2,'UNIQUE_PATCH_ANCHOR: '+reason);
 changes.push({reason,before_sha256:sha(oldText),after_sha256:sha(newText),before:oldText,after:newText});
 return sql.replace(oldText,()=>newText);
}
function central(sql,changes){
 sql=change(sql,anchor,providerCTE+anchor,changes,'Carry the accepted exact managed-reader eligibility into the replacement seal');
 return change(sql,read,read+extraRead,changes,'Exempt only measured inherited SELECT; retain explicit table/column/PUBLIC ACL rejection');
}
function aclRows(array,kind,owner){
 return `pg_catalog.aclexplode(CASE WHEN ${array} IS NULL THEN pg_catalog.acldefault('${kind}',${owner}) WHEN pg_catalog.cardinality(${array})>0 THEN ${array} ELSE NULL::aclitem[] END)`;
}
function explicitTableACL(){
 return `EXISTS(SELECT 1 FROM (
          SELECT a.grantee FROM ${aclRows('c.relacl','r','c.relowner')} a WHERE a.privilege_type='SELECT'
          UNION ALL
          SELECT a.grantee FROM pg_catalog.pg_attribute att CROSS JOIN LATERAL
            pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(att.attacl)>0 THEN att.attacl ELSE NULL::aclitem[] END) a
            WHERE att.attrelid=c.oid AND att.attnum>0 AND NOT att.attisdropped AND a.privilege_type='SELECT'
        ) app_acl WHERE CASE WHEN app_acl.grantee=0 THEN true ELSE pg_catalog.pg_has_role(r.oid,app_acl.grantee,'USAGE') END)`;
}
function privateGuard(sql,schema,label,changes){
 const declaration='DECLARE m record; function_row record; r record; owner_id oid:=(SELECT datdba FROM pg_database WHERE datname=current_database());';
 sql=change(sql,declaration,declaration.replace('r record;','r record; managed_reader boolean;'),changes,'Track measured managed-reader eligibility without skipping any role');
 const oldGlobal=`    IF pg_has_role(r.oid,'pg_read_all_data','MEMBER') OR pg_has_role(r.oid,'pg_write_all_data','MEMBER') THEN\n      RETURN NEXT '${label}_inherited_global_data:'||r.rolname; END IF;`;
 const privateEligibility=providerCTE.replace(/\br\./g,'measured.').replace('pg_catalog.pg_roles r ON','pg_catalog.pg_roles measured ON').replace(/\bm\.sig\b/g,'gate_rpc.sig').replace('acl_manifest m','acl_manifest gate_rpc');
 const qualify=`    -- Same eligibility predicate as accepted A1; SQL aliases are renamed
    -- to avoid PL/pgSQL loop-variable ambiguity. Own manifest RPCs
    -- must also be inaccessible. Never skip a role or exempt writes.
    WITH nonroot AS (SELECT r.oid,r.rolname),
      acl_manifest(sig) AS (SELECT name FROM ${schema}.manifest WHERE kind='function')
      ${privateEligibility}
    SELECT EXISTS(SELECT 1 FROM managed_readers) INTO managed_reader;
    IF (pg_has_role(r.oid,'pg_read_all_data','MEMBER') AND NOT managed_reader)
      OR pg_has_role(r.oid,'pg_write_all_data','MEMBER') THEN
      RETURN NEXT '${label}_inherited_global_data:'||r.rolname; END IF;`;
 sql=change(sql,oldGlobal,qualify,changes,'Recognize exact existing read-all membership, preserve every write-all and unknown-member rejection');
 const oldSchema=`    IF has_schema_privilege(r.oid,'${schema}','USAGE,CREATE') THEN RETURN NEXT '${label}_schema_privilege:'||r.rolname; END IF;`;
 const newSchema=`    IF has_schema_privilege(r.oid,'${schema}','CREATE')
      OR (has_schema_privilege(r.oid,'${schema}','USAGE') AND NOT managed_reader)
      OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL ${aclRows('n.nspacl','n','n.nspowner')} a
        WHERE n.nspname='${schema}' AND a.privilege_type IN ('USAGE','CREATE')
          AND CASE WHEN a.grantee=0 THEN true ELSE pg_catalog.pg_has_role(r.oid,a.grantee,'USAGE') END)
      THEN RETURN NEXT '${label}_schema_privilege:'||r.rolname; END IF;`;
 sql=change(sql,oldSchema,newSchema,changes,'Separate implicit read-all schema USAGE from CREATE and explicit/inherited application schema ACL');
 const oldTable="      AND (has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')\n        OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))";
 const newTable=`      AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
        OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')
        OR ((has_table_privilege(r.oid,c.oid,'SELECT') OR has_any_column_privilege(r.oid,c.oid,'SELECT')) AND NOT managed_reader)
        OR ${explicitTableACL()}))`;
 return change(sql,oldTable,newTable,changes,'Preserve all write/column guards, add MAINTAIN, reject explicit SELECT while recognizing only inherited global read');
}
export function align(manifest,app,accepted){
 assert.equal(sha(accepted),ACCEPTED_A1,'ACCEPTED_A1_DRIFT');
 const results=[];let previousSeal=bodyMD5(accepted.toString());
 for(const step of manifest.steps.filter(s=>s.order>=8)){
  const original=fs.readFileSync(path.join(app,step.path));assert.equal(sha(original),step.sha256,'SOURCE_DRIFT:'+step.path);
  const changes=[];let sql=original.toString();const originalSql=sql;
  if(step.order===8){sql=accepted.toString();changes.push({reason:'Accepted Director-G1 candidate, byte-for-byte',before:originalSql,after:sql});}
  if(step.order===9||step.order===10){
   const originalExpected=step.order===9?'4038bd50bbb0863029efd11f86a9616e':'e6612a673d5bdf4e30135c02a54dbda1';
   sql=change(sql,"md5(prosrc)='"+originalExpected+"'","md5(prosrc)='"+previousSeal+"'",changes,'Pin the exact body computed from the immediately preceding aligned seal, not arbitrary acceptance');
   sql=central(sql,changes);previousSeal=bodyMD5(sql);
  }
  if(step.order===13)sql=privateGuard(sql,'phoenix_c4','c4',changes);
  if(step.order===15)sql=privateGuard(sql,'phoenix_monthly','monthly',changes);
  // Reverse every replacement in reverse order: all non-guard business bytes survive.
  let reverse=sql;for(const c of [...changes].reverse())reverse=reverse.replace(c.after,()=>c.before);assert.equal(reverse,originalSql,'UNRELATED_BYTES_CHANGED');
  results.push({...step,original_sha256:step.sha256,sha256:sha(sql),sql,changes,
   central_seal_body_md5:previousSeal,changed:sql!==originalSql});
 }
 return results;
}
const here=path.dirname(fileURLToPath(import.meta.url));
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const root=path.resolve(here,'../..'),manifest=JSON.parse(fs.readFileSync(path.join(root,'work/continuity-r33/R33/STAGING_SQL_MANIFEST.json')));
 const accepted=fs.readFileSync(path.join(root,'work/r33-p3a1-compat/P3A1_annual_catalog_R33_COMPAT_REVIEW_ONLY.sql'));
 const results=align(manifest,path.join(root,'work/medistock-r33'),accepted);
 fs.mkdirSync(path.join(here,'SQL'),{recursive:true});
 for(const r of results)fs.writeFileSync(path.join(here,'SQL',path.basename(r.path)),r.sql);
 const review={status:'DRAFT_ALIGNED_STATIC_ONLY_RUNTIME_NOT_RUN',target:manifest.target,source_head:manifest.head,
   accepted_step8_sha256:ACCEPTED_A1,never_reapply_staging:[1,2,3,4,5,6,7],hosted_apply_authorized:false,
   steps:results.map(({sql,changes,...r})=>({...r,path:'SQL/'+path.basename(r.path),source_path:r.path,change_reasons:changes.map(c=>c.reason)}))};
 fs.writeFileSync(path.join(here,'CHAIN_REVIEW_MANIFEST.json'),JSON.stringify(review,null,2));
 fs.writeFileSync(path.join(here,'EXACT_CHANGE_PROVENANCE.json'),JSON.stringify(results.map(({order,changes})=>({order,changes})),null,2));
 console.log(JSON.stringify(review,null,2));
}
