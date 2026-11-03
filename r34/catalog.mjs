export const catalogSQL=`SELECT jsonb_build_object(
 'schemas',(SELECT jsonb_agg(jsonb_build_array(nspname,pg_get_userbyid(nspowner),coalesce(nspacl,acldefault('n',nspowner))::text) ORDER BY nspname) FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname<>'information_schema'),
 'types',(SELECT jsonb_agg(jsonb_build_array(n.nspname,t.typname,t.typtype,t.typcategory,pg_get_userbyid(t.typowner),t.typacl::text,t.typnotnull,t.typdefault,format_type(t.typbasetype,t.typtypmod),(SELECT jsonb_agg(enumlabel ORDER BY enumsortorder) FROM pg_enum WHERE enumtypid=t.oid)) ORDER BY n.nspname,t.typname) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
 'event_triggers',(SELECT jsonb_agg(jsonb_build_array(evtname,evtevent,pg_get_userbyid(evtowner),evtfoid::regprocedure::text,evtenabled,evttags) ORDER BY evtname) FROM pg_event_trigger),
 'publications',(SELECT jsonb_agg(jsonb_build_array(pubname,pg_get_userbyid(pubowner),puballtables,pubinsert,pubupdate,pubdelete,pubtruncate,pubviaroot) ORDER BY pubname) FROM pg_publication),
 'publication_tables',(SELECT jsonb_agg(to_jsonb(t) ORDER BY pubname,schemaname,tablename) FROM pg_publication_tables t),
 'large_objects',(SELECT jsonb_agg(jsonb_build_array(m.oid::text,pg_get_userbyid(m.lomowner),m.lomacl::text,encode(sha256(lo_get(m.oid)),'hex')) ORDER BY m.oid) FROM pg_largeobject_metadata m),
 'database_settings',(SELECT jsonb_agg(jsonb_build_array(coalesce(d.datname,'*'),coalesce(r.rolname,'*'),s.setconfig) ORDER BY coalesce(d.datname,'*'),coalesce(r.rolname,'*')) FROM pg_db_role_setting s LEFT JOIN pg_database d ON d.oid=s.setdatabase LEFT JOIN pg_roles r ON r.oid=s.setrole),
 'domain_constraints',(SELECT jsonb_agg(jsonb_build_array(n.nspname,t.typname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) ORDER BY n.nspname,t.typname,k.conname) FROM pg_constraint k JOIN pg_type t ON t.oid=k.contypid JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname !~ '^pg_'),
 'extensions',(SELECT jsonb_agg(jsonb_build_array(extname,extversion,n.nspname) ORDER BY extname) FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace),
 'functions',(SELECT jsonb_agg(jsonb_build_array(n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),p.prokind,(SELECT lanname FROM pg_language WHERE oid=p.prolang),format_type(p.prorettype,NULL),pg_get_function_arguments(p.oid),p.proleakproof,p.proparallel,p.proisstrict,p.proretset,p.procost,p.prorows,p.prosrc,p.probin,p.prosecdef,p.provolatile,p.proconfig,pg_get_userbyid(p.proowner),coalesce(p.proacl,acldefault('f',p.proowner))::text) ORDER BY n.nspname,p.proname,pg_get_function_identity_arguments(p.oid)) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
 'relations',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner),coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 's'::\"char\" ELSE 'r'::\"char\" END,c.relowner))::text) ORDER BY n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','S')),
 'columns',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,a.attname,format_type(a.atttypid,a.atttypmod),a.attnotnull,pg_get_expr(d.adbin,d.adrelid),a.attacl::text,a.attidentity,a.attgenerated) ORDER BY n.nspname,c.relname,a.attnum) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p')),
 'policies',(SELECT jsonb_agg(to_jsonb(x) ORDER BY schemaname,tablename,policyname) FROM pg_policies x),
 'triggers',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,pg_get_triggerdef(t.oid),t.tgenabled) ORDER BY n.nspname,c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT t.tgisinternal AND n.nspname !~ '^pg_'),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,k.conname,pg_get_constraintdef(k.oid),k.convalidated) ORDER BY n.nspname,c.relname,k.conname) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname !~ '^pg_'),
 'indexes',(SELECT jsonb_agg(to_jsonb(x) ORDER BY schemaname,indexname) FROM pg_indexes x WHERE schemaname !~ '^pg_'),
 'roles',(SELECT jsonb_agg(jsonb_build_array(rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls,rolconnlimit,rolconfig) ORDER BY rolname) FROM pg_roles WHERE rolname !~ '^pg_' AND rolname<>'r34_recovery_owner'),
 'memberships',(SELECT jsonb_agg(jsonb_build_array(r.rolname,m.rolname,g.rolname,a.admin_option,a.inherit_option,a.set_option) ORDER BY r.rolname,m.rolname,g.rolname) FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor),
 'default_acl',(SELECT jsonb_agg(jsonb_build_array(pg_get_userbyid(d.defaclrole),n.nspname,d.defaclobjtype,d.defaclacl::text) ORDER BY pg_get_userbyid(d.defaclrole),n.nspname,d.defaclobjtype) FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace)
 ) AS catalog`;
const quote=s=>'"'+s.replaceAll('"','""')+'"';
export async function originalData(c,projection){
 const rows=[];
 for(const item of projection){
  const columns=item.columns.map(quote).join(',');
  const x=(await c.query(`SELECT count(*)::text rows,md5(coalesce(string_agg(md5(row_to_json(t)::text),'' ORDER BY md5(row_to_json(t)::text) COLLATE "C"),'')) digest FROM (SELECT ${columns} FROM ${item.table}) t`)).rows[0];
  rows.push({table:item.table,columns:item.columns,...x});
 }
 return rows;
}
export async function snapshot(c){
 const catalog=(await c.query(catalogSQL)).rows[0].catalog;
 const tables=(await c.query("SELECT schemaname,tablename FROM pg_tables WHERE schemaname !~ '^pg_' AND schemaname<>'information_schema' ORDER BY 1,2")).rows;
 const data=[];
 for(const t of tables){const table=`${quote(t.schemaname)}.${quote(t.tablename)}`;const x=(await c.query(`SELECT count(*)::text AS rows,md5(coalesce(string_agg(md5(row_to_json(t)::text),'' ORDER BY md5(row_to_json(t)::text) COLLATE "C"),'')) AS digest FROM ${table} t`)).rows[0];data.push({table,...x});}
 const seqs=(await c.query("SELECT schemaname,sequencename FROM pg_sequences WHERE schemaname !~ '^pg_' ORDER BY 1,2")).rows;
 const sequences=[];for(const s of seqs){const name=`${quote(s.schemaname)}.${quote(s.sequencename)}`;sequences.push({name,...(await c.query(`SELECT last_value::text,is_called FROM ${name}`)).rows[0]});}
 return {catalog,data,sequences};
}
export async function originalProjection(c){
 const result=(await c.query(`SELECT quote_ident(n.nspname)||'.'||quote_ident(t.relname) AS table,json_agg(a.attname ORDER BY a.attnum) columns FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum>0 AND NOT a.attisdropped WHERE t.relkind IN ('r','p') AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema' GROUP BY n.nspname,t.relname ORDER BY n.nspname,t.relname`)).rows;
 return originalData(c,result);
}
