// Deployment tooling only; the Worker itself executes Rust/WASM.
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { parseArgs } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { zstdCompressSync, constants } from 'node:zlib';
import { blake3 } from '@noble/hashes/blake3.js';

const {values:{url,namespace}}=parseArgs({options:{url:{type:'string'},namespace:{type:'string'}}});
assert.ok(url && namespace && process.env.MBX_REMOTE_TOKEN, 'provide --url, --namespace and MBX_REMOTE_TOKEN');
const headers={'mbx-cache-protocol':'1','mbx-cache-namespace':namespace,
  authorization:`Bearer ${process.env.MBX_REMOTE_TOKEN}`};
async function request(path,method='GET',body,extra={}) {
  return fetch(url.replace(/\/$/,'')+path,{method,body,headers:{...headers,...extra},signal:AbortSignal.timeout(60_000)});
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value==='object') return Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])]));
  return value;
}
const encode=value=>Buffer.from(JSON.stringify(canonical(value)));
function digest(bytes,algorithm='sha256') {
  return {algorithm,hash:algorithm==='blake3'?Buffer.from(blake3(bytes)).toString('hex'):createHash('sha256').update(bytes).digest('hex'),size:bytes.length};
}
const path=(kind,d)=>`/v1/${kind}/${d.algorithm}/${d.hash}/${d.size}`;
async function put(bytes,algorithm='sha256',encoded=bytes,extra={}) {
  const d=digest(bytes,algorithm),response=await request(path('blobs',d),'PUT',encoded,{'if-none-match':'*',...extra});
  assert.ok([201,204].includes(response.status),`${response.status}: ${await response.text()}`);
  return d;
}
async function hit(uri,expected) {
  const statuses=[];
  for (let attempt=0;attempt<10;attempt++) {
    const response=await request(uri);
    // An unconstrained replica can briefly miss a preceding request's write.
    if(response.status===404) {await response.arrayBuffer();await delay(250);continue;}
    assert.equal(response.status,200,await response.clone().text());
    const body=Buffer.from(await response.arrayBuffer());
    assert.deepEqual(Buffer.isBuffer(expected)?body:JSON.parse(body.toString()),expected);
    assert.equal(response.headers.get('cache-control'),'private, no-store');
    statuses.push(response.headers.get('mbx-cache-edge-status'));
    if(statuses.at(-1)==='HIT') {
      console.log(JSON.stringify({resource:uri.split('/')[2],cache_statuses:statuses,bytes:body.length}));
      return;
    }
    await delay(250);
  }
  assert.fail(`no real Workers Cache HIT: ${statuses}`);
}

const bytes=Buffer.from(`mbx-workers-smoke-${randomUUID()}`),d=digest(bytes),uri=path('blobs',d);
assert.equal((await request(uri)).status,404);
await put(bytes);
await hit(uri,bytes);
assert.equal((await request(uri,'GET',undefined,{authorization:'Bearer invalid-smoke-token'})).status,401);
assert.ok([403,404].includes((await request(uri,'GET',undefined,{'mbx-cache-namespace':namespace+'-cache-probe'})).status));
const head=await request(uri,'HEAD');
assert.equal(head.status,200);
assert.equal(head.headers.get('mbx-cache-edge-status'),'HIT');
assert.equal((await head.arrayBuffer()).byteLength,0);
const packed=await request('/v1/blobs:pack','POST',encode({digests:[d]}));
const size=Buffer.alloc(8);size.writeBigUInt64BE(BigInt(d.size));
assert.equal(packed.status,200);
assert.deepEqual(Buffer.from(await packed.arrayBuffer()),Buffer.concat([Buffer.from('MBXPACK1'),Buffer.from([2]),Buffer.from(d.hash,'hex'),size,bytes]));

const action=await put(encode({arch:'x86_64',args:[],command_inputs:[],dependency_keys:[],
  environment:{},kind:'task',os:'linux',outputs:[],phase:'normal',root:'.',run:['true'],
  shell:null,source_hash:randomUUID(),task:'worker-smoke',tools:[],vars:{},version:1}),'blake3');
const result={action,metadata:null,output_root:null,version:1};
const resultUri=path('action-results',action);
const committed=await request(resultUri,'PUT',encode(result),{'if-none-match':'*'});
assert.ok([201,204].includes(committed.status),`${committed.status}: ${await committed.text()}`);
await hit(resultUri,result);
const batch=await request('/v1/action-results:batch','POST',encode({digests:[action]}));
assert.equal(batch.status,200);
assert.deepEqual(await batch.json(),{results:[result]});

const expanded=Buffer.alloc(8*1024*1024);
expanded.fill(`mbx-zstd-smoke-${randomUUID()}`);
const compressed=zstdCompressSync(expanded,{params:{[constants.ZSTD_c_windowLog]:20}});
const zstdDigest=await put(expanded,'sha256',compressed,{'content-encoding':'zstd'});
await hit(path('blobs',zstdDigest),expanded);
console.log('Deployed Worker smoke passed: blobs, actions, packs, batches, HEAD, zstd, auth, real edge HITs.');
