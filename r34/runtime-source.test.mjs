import {test} from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
test('Linux bootstrap remains LF encoded after Windows edits',()=>{
 const bytes=fs.readFileSync(new URL('./restore-runtime.sh',import.meta.url));
 assert.equal(bytes.includes(13),false,'CRLF breaks the Linux shell before boot diagnostics');
 assert.ok(bytes.toString().startsWith('#!/usr/bin/env bash\n'));
});
