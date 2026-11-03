import crypto from 'node:crypto';import assert from 'node:assert/strict';
import {TARGET} from './policy.mjs';
export const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const aad=Buffer.from('MediStock-R34-Production-Recovery:'+TARGET);
export function encrypt(bytes,publicPEM){
 const pub=crypto.createPublicKey(publicPEM);assert.equal(pub.asymmetricKeyType,'rsa');assert.ok(pub.asymmetricKeyDetails.modulusLength>=3072);
 const key=crypto.randomBytes(32),iv=crypto.randomBytes(12),cipher=crypto.createCipheriv('aes-256-gcm',key,iv);cipher.setAAD(aad);
 try{return Buffer.from(JSON.stringify({format:'R34_PRODUCTION_AES256GCM_RSAOAEP_SHA256_V1',target:TARGET,iv:iv.toString('base64'),ciphertext:Buffer.concat([cipher.update(bytes),cipher.final()]).toString('base64'),authentication_tag:cipher.getAuthTag().toString('base64'),wrapped_key:crypto.publicEncrypt({key:pub,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},key).toString('base64')}));}finally{key.fill(0);}
}
export function decrypt(bytes,privatePEM){
 const x=JSON.parse(bytes);assert.equal(x.target,TARGET);assert.equal(x.format,'R34_PRODUCTION_AES256GCM_RSAOAEP_SHA256_V1');
 const key=crypto.privateDecrypt({key:privatePEM,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},Buffer.from(x.wrapped_key,'base64'));
 try{assert.equal(key.length,32);const d=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(x.iv,'base64'));d.setAAD(aad);d.setAuthTag(Buffer.from(x.authentication_tag,'base64'));return Buffer.concat([d.update(Buffer.from(x.ciphertext,'base64')),d.final()]);}finally{key.fill(0);}
}
export function transferURL(text,runId){
 const u=new URL(text);assert.equal(u.protocol,'https:');assert.equal(u.hostname,'be10f48bad134b7947d7e25e04a1765c.r2.cloudflarestorage.com');
 assert.ok(!u.username&&!u.password&&!u.port);assert.match(String(runId),/^[0-9]+$/);
 assert.equal(u.pathname,'/medistock-production-recovery-r34/r34/'+runId+'/production.r34');
 assert.ok(u.searchParams.has('X-Amz-Signature'));assert.ok(Number(u.searchParams.get('X-Amz-Expires'))<=7200&&Number(u.searchParams.get('X-Amz-Expires'))>0);return u;
}
