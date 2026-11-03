import {test} from 'node:test';import assert from 'node:assert/strict';import crypto from 'node:crypto';
import {encrypt,decrypt,transferURL} from './recovery-crypto.mjs';
test('independent private key recovers exact bytes; tampering and wrong target rejected',()=>{
 const pair=crypto.generateKeyPairSync('rsa',{modulusLength:3072,publicKeyEncoding:{type:'spki',format:'pem'},privateKeyEncoding:{type:'pkcs8',format:'pem'}}),plain=Buffer.from('Synthetic R34 archive only'),blob=encrypt(plain,pair.publicKey);
 assert.deepEqual(decrypt(blob,pair.privateKey),plain);
 const original=JSON.parse(blob);for(const change of [{target:'knndhlczdlparjfmlxis'},{authentication_tag:Buffer.alloc(16).toString('base64')},{ciphertext:Buffer.from('changed').toString('base64')}])assert.throws(()=>decrypt(Buffer.from(JSON.stringify({...original,...change})),pair.privateKey));
 assert.throws(()=>encrypt(plain,'invalid public key'));
});
test('R2 signed URL restricted to exact account, bucket, run and object',()=>{
 const url='https://be10f48bad134b7947d7e25e04a1765c.r2.cloudflarestorage.com/medistock-production-recovery-r34/r34/123/production.r34?X-Amz-Signature=synthetic&X-Amz-Expires=3600';transferURL(url,'123');
 for(const v of [url.replace('https:','http:'),url.replace('be10f48bad134b7947d7e25e04a1765c','other'),url.replace('recovery-r34','other-bucket'),url.replace('/123/','/124/'),url.replace('3600','7201')])assert.throws(()=>transferURL(v,'123'));
});
