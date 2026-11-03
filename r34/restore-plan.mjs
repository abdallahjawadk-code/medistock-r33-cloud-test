import assert from 'node:assert/strict';
// pg_dump does not archive extension owners. Recreate those real extensions
// from captured catalog metadata, retaining every other native TOC entry.
export function restorePlan(toc,extensions){
 const headers=[],initial=[],remaining=[],extensionEntries=[],ids=new Set();
 const namespaces=new Set(extensions.map(x=>x[2]).filter(x=>x!=='pg_catalog'));
 const schemas=new Set();let databases=0;
 for(const line of toc.split('\n')){
  if(!line||line.startsWith(';')){headers.push(line);continue;}
  const row=line.match(/^(\d+);\s+\d+\s+\d+\s+(.*)$/);assert.ok(row,'TOC_FORMAT');assert.ok(!ids.has(row[1]),'DUPLICATE_TOC_ID');ids.add(row[1]);
  if(/^DATABASE\s+-\s+postgres\s/.test(row[2])){databases++;initial.push(line);continue;}
  if(/^DATABASE PROPERTIES\s+-\s+postgres(?:\s|$)/.test(row[2])||/^(?:ACL|COMMENT|SECURITY LABEL)\s+-\s+DATABASE postgres(?:\s|$)/.test(row[2])){initial.push(line);continue;}
  const schema=row[2].match(/^SCHEMA\s+-\s+(\S+)\s/);
  if(schema&&namespaces.has(schema[1])){assert.ok(!schemas.has(schema[1]));schemas.add(schema[1]);initial.push(line);continue;}
  const extension=row[2].match(/^EXTENSION\s+-\s+(\S+)(?:\s|$)/);
  if(extension){assert.ok(extensions.some(x=>x[0]===extension[1]),'UNRECORDED_EXTENSION');assert.ok(!extensionEntries.includes(extension[1]));extensionEntries.push(extension[1]);continue;}
  remaining.push(line);
 }
 const declared=toc.match(/^;\s*TOC Entries:\s*(\d+)\s*$/m);assert.ok(declared,'DECLARED_TOC_COUNT');assert.equal(ids.size,Number(declared[1]),'ALL_NATIVE_TOC_IDS_LISTED');
 assert.equal(databases,1,'EXACT_DATABASE_ENTRY');assert.deepEqual([...schemas].sort(),[...namespaces].sort(),'EXTENSION_SCHEMAS_PRESENT');
 for(const x of extensions)if(x[0]!=='plpgsql')assert.ok(extensionEntries.includes(x[0]),'EXTENSION_TOC_COVERAGE');
 assert.equal(initial.length+remaining.length+extensionEntries.length,ids.size,'COMPLETE_TOC_PARTITION');
 initial.sort((a,b)=>Number(/ DATABASE - /.test(b))-Number(/ DATABASE - /.test(a)));
 const render=rows=>headers.concat(rows).join('\n')+'\n';
 return {initial:render(initial),remaining:render(remaining),total:ids.size,initial_entries:initial.length,remaining_entries:remaining.length,extension_entries:extensionEntries.length};
}
