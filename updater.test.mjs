import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { BASE, hash, checkRelease, checkData, checkVersion, getFile, receive } from './updater.mjs';

const pair = generateKeyPairSync('ed25519');
const key = pair.publicKey.export({type:'spki',format:'pem'});
const data = Buffer.from('Hello World!\n');
const sha256 = hash(data);
const now = Date.now();
const m = {schema:1,source:BASE,version:1,file:`${sha256}.bin`,size:data.length,sha256,created:new Date(now).toISOString(),expires:new Date(now+3600000).toISOString()};
function envelope(manifest=m) {
  const b = Buffer.from(JSON.stringify(manifest));
  return Buffer.from(JSON.stringify({payload:b.toString('base64'),signature:sign(null,b,pair.privateKey).toString('base64')}));
}
test('signed release and bytes accepted',()=>checkData(data,checkRelease(envelope(),key)));
test('signature tampering rejected',()=>{
 const e=JSON.parse(envelope());e.signature=Buffer.alloc(64).toString('base64');
 assert.throws(()=>checkRelease(Buffer.from(JSON.stringify(e)),key),/signature/);
});
test('payload tampering rejected',()=>assert.throws(()=>checkData(Buffer.from('changed'),m),/integrity/));
test('wrong key rejected',()=>assert.throws(()=>checkRelease(envelope(),generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'})),/signature/));
for (const [name,change] of Object.entries({expired:{expires:new Date(now-1).toISOString()},traversal:{file:'../file'},origin:{source:'https://example.com/'},size:{size:17000000},version:{version:0}})) {
 test(`signed ${name} refused`,()=>assert.throws(()=>checkRelease(envelope({...m,...change}),key),/policy/));
}
test('rollback rejected',()=>assert.throws(()=>checkVersion({version:2,sha256},m),/Rollback/));
test('same version with different data rejected',()=>assert.throws(()=>checkVersion({version:1,sha256:'a'.repeat(64)},m),/conflicting/));
test('unapproved path refused without request',async()=>assert.rejects(getFile('../secret',100,()=>{throw Error('network used');}),/Unapproved/));

function fakeRequest(status,body,onOptions=()=>{}) {
 return (url,options,cb)=>{
  onOptions(url,options);
  const req=new EventEmitter();
  req.destroy=e=>{if(e)req.emit('error',e);req.emit('close');};
  req.end=(...args)=>{
   assert.equal(args.length,0);
   queueMicrotask(()=>{const res=new PassThrough();res.statusCode=status;cb(res);res.end(body);req.emit('close');});
  };
  return req;
 };
}
test('transport emits bodyless GET with TLS validation',async()=>{
 const result=await getFile('release.json',100,fakeRequest(200,Buffer.from('ok'),(url,o)=>{
  assert.equal(url,BASE+'release.json');assert.equal(o.method,'GET');assert.equal(o.rejectUnauthorized,true);assert.equal(o.headers.Authorization,undefined);
 }));assert.equal(result.toString(),'ok');
});
test('redirect refused',async()=>assert.rejects(getFile('release.json',100,fakeRequest(302,Buffer.alloc(0))),/302/));
test('policy 403 refused without fallback',async()=>assert.rejects(getFile('release.json',100,fakeRequest(403,Buffer.alloc(0))),/403/));
test('oversized HTTP response refused',async()=>assert.rejects(getFile('release.json',1,fakeRequest(200,Buffer.from('big'))),/large/));
test('verified staging and repeat run',async()=>{
 const root=await mkdtemp(join(tmpdir(),'updater-test-'));const calls=[];
 try {
  await writeFile(join(root,'trusted-key.pem'),key);
  const get=async name=>{calls.push(name);return name==='release.json'?envelope():data;};
  const result=await receive({root,get});assert.equal(result.status,'verified');
  assert.deepEqual(await readFile(result.output),data);
  assert.equal((await receive({root,get})).status,'already-current');
  assert.deepEqual(calls,['release.json',m.file,'release.json']);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('invalid bytes leave no saved payload or state',async()=>{
 const root=await mkdtemp(join(tmpdir(),'updater-test-'));
 try{await writeFile(join(root,'trusted-key.pem'),key);await assert.rejects(receive({root,get:async n=>n==='release.json'?envelope():Buffer.from('bad')}),/integrity/);assert.deepEqual(await readdir(join(root,'inbox')),[]);}
 finally{await rm(root,{recursive:true,force:true});}
});
