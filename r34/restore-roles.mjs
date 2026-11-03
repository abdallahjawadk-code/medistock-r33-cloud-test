import assert from 'node:assert/strict';
// initdb's OID-10 role is verified against Production: supabase_admin.
// Preserve the original archive. Only omit its redundant CREATE in the replay;
// every ALTER, password verifier, setting and membership is still replayed.
export function roleReplay(bytes){
 const text=bytes.toString('utf8'),create=/^CREATE ROLE supabase_admin;\r?$/gm;
 assert.equal([...text.matchAll(create)].length,1,'EXACT_BOOTSTRAP_CREATE');
 assert.match(text,/^ALTER ROLE supabase_admin WITH .*\bSUPERUSER\b/m,'BOOTSTRAP_ATTRIBUTES_PRESENT');
 return Buffer.from(text.replace(create,'-- R34: OID-10 bootstrap role already exists; all attributes restored below.'));
}
