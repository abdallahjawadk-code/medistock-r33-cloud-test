import assert from 'node:assert/strict';
export const sourceContractSQL=`SELECT
 ((SELECT count(*) FROM pg_roles WHERE rolname IN ('anon','authenticated'))=2 AND NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('anon','authenticated') AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))) AS api_roles_safe,
 to_regclass('public.central_needs_catalog_years') IS NULL AS annual_catalog_absent,
 to_regnamespace('phoenix_c4') IS NULL AS c4_absent,
 to_regnamespace('phoenix_monthly') IS NULL AS monthly_absent,
 (SELECT jsonb_build_object('sha256',encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex'),'owner',pg_get_userbyid(p.proowner),'acl',p.proacl::text,'security_definer',p.prosecdef,'config',p.proconfig) FROM pg_proc p WHERE p.oid=to_regprocedure('phoenix_private.central_needs_capability_breaches_v1()')) AS seal,
 (SELECT jsonb_agg(jsonb_build_object('name',p.proname,'md5',md5(p.prosrc)) ORDER BY p.proname) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='phoenix_private' AND p.proname IN ('central_needs_sod_excluded_v1','central_material_assert_reviewer_v1','central_needs_staffing_readiness_v1')) AS predecessors`;
const expected={central_needs_sod_excluded_v1:'1b179e1da2075816a072c1f6a9935167',central_material_assert_reviewer_v1:'75f420c1cf7b80d2bffdb07609ee7b76',central_needs_staffing_readiness_v1:'401791829f66ce810a1cb77cedf5aa5a'};
export async function verifySourceContract(c){
 const row=(await c.query(sourceContractSQL)).rows[0];
 for(const key of ['api_roles_safe','annual_catalog_absent','c4_absent','monthly_absent'])assert.equal(row[key],true,'SOURCE_CONTRACT_'+key);
 assert.deepEqual(row.seal,{sha256:'a65980681b84a1cea146c45497aaaf35176a3ec1a7d05c5fe66aa1f56ccf23d3',owner:'postgres',acl:'{postgres=X/postgres}',security_definer:false,config:['search_path=pg_catalog, pg_temp']},'SOURCE_SEAL_DEFINITION_OWNER_ACL_CONFIG_DRIFT');
 assert.equal(row.predecessors?.length,3,'SOURCE_PREDECESSOR_COUNT');assert.deepEqual(Object.fromEntries(row.predecessors.map(x=>[x.name,x.md5])),expected,'SOURCE_PREDECESSOR_BODY_DRIFT');
}
