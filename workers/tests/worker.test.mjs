import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, generateKeyPairSync, sign, constants as cconst } from 'node:crypto';
import { zstdCompressSync, constants as zconst } from 'node:zlib';
import { setTimeout as delay } from 'node:timers/promises';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { blake3 } from '@noble/hashes/blake3.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const packType = 'application/vnd.mbx.cache-blob-pack.v1';
let mf, db, bucket;
let oidcKeys, rotatedKeys, ecKeys, ec384Keys, edKeys;
let rotated=false, failFallback=false;
const outboundCounts=new Map();
const providers=['issuer','direct','mismatch','fallback'].map(name=>({
  issuer:`https://${name}.test`,audiences:['https://cache.example'],
  ...(name==='direct'?{jwks_uri:'https://direct.test/keys'}:{}),
  algorithms:['RS256','RS384','RS512','PS256','PS384','PS512','ES256','ES384','EdDSA'],jwks_refresh_seconds:1,clock_skew_seconds:0,
  rules:[
    {claims:{repository:'acme/project',repository_owner_id:'123'},read:['test/*'],write:[]},
    {claims:{repository:'acme/project',repository_owner_id:'123',event_name:'push',ref_type:'branch',ref:'refs/heads/main'},read:['test/*'],write:['test/*']},
    {claims:{groups:['ci','build'],trusted:true,level:2},read:['test/*'],write:[]},
  ],
}));
function jwk(keys,kid,alg='RS256',extra={}) {
  return {...keys.publicKey.export({format:'jwk'}),kid,alg,use:'sig',key_ops:['verify'],...extra};
}
async function outbound(request) {
  const url=new URL(request.url);
  outboundCounts.set(url.href,(outboundCounts.get(url.href)||0)+1);
  if (url.pathname==='/.well-known/openid-configuration') {
    return Response.json({issuer:url.hostname==='mismatch.test'?'https://wrong.test':url.origin,
      jwks_uri:`${url.origin}/keys`,id_token_signing_alg_values_supported:['RS256','RS384','RS512','PS256','PS384','PS512','ES256','ES384','EdDSA']});
  }
  if (url.pathname==='/keys') {
    if (url.hostname==='fallback.test' && failFallback) return new Response('unavailable',{status:503});
    const keys=url.hostname==='issuer.test' && rotated?rotatedKeys:oidcKeys;
    return Response.json({keys:[
      jwk(keys,rotated && url.hostname==='issuer.test'?'rotated-key':'rsa-key'),
      jwk(ecKeys,'ec-key','ES256'),jwk(ec384Keys,'ec384-key','ES384'),jwk(edKeys,'ed-key','EdDSA'),
      ...['RS384','RS512','PS256','PS384','PS512'].map(alg=>jwk(keys,`${alg}-key`,alg)),
      jwk(oidcKeys,'bad-use','RS256',{use:'enc'}),
      jwk(oidcKeys,'bad-alg','RS512'),jwk(oidcKeys,'bad-ops','RS256',{key_ops:['sign']}),
    ]});
  }
  return new Response('not found',{status:404});
}
function jwt(claims={},options={}) {
  const algorithm=options.algorithm||'RS256';
  const key=options.key||oidcKeys.privateKey;
  const header={alg:algorithm,kid:options.kid||'rsa-key',typ:'JWT',...options.header};
  const payload={iss:'https://issuer.test',aud:'https://cache.example',sub:'repo:acme/project',
    exp:Math.floor(Date.now()/1000)+300,repository:'acme/project',repository_owner_id:'123',
    event_name:'push',ref_type:'branch',ref:'refs/heads/main',...claims};
  const input=[header,payload].map(v=>Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
  const signature=algorithm==='HS256'?createHmac('sha256','secret').update(input).digest():
    sign(algorithm==='EdDSA'?null:algorithm.endsWith('384')?'sha384':algorithm.endsWith('512')?'sha512':'sha256',Buffer.from(input),
      algorithm.startsWith('ES')?{key,dsaEncoding:'ieee-p1363'}:
      algorithm.startsWith('PS')?{key,padding:cconst.RSA_PKCS1_PSS_PADDING,saltLength:algorithm.endsWith('384')?48:algorithm.endsWith('512')?64:32}:key);
  return `${input}.${signature.toString('base64url')}`;
}
function runtime(bindings={}) {
  return new Miniflare(convertV4MiniflareOptions({ workers: [{
    name: "mbx-cache",
    modulesRoot: `${root}build`,
    modules: [
      {type:'ESModule',path:`${root}build/index.js`},
      {type:'CompiledWasm',path:`${root}build/index_bg.wasm`},
    ],
    outboundService: outbound,
    compatibilityDate: '2026-10-28',
    d1Databases: ['MBX_DB'], r2Buckets: ['MBX_BLOBS'],
    bindings: {
      MBX_CACHE_TOKENS_JSON: JSON.stringify([
        { token: 'test-token', read: ['test/*'], write: ['test/*'] },
        { token: 'read-token', read: ['test/*'], write: [] },
      ]),
      MBX_CACHE_ANONYMOUS_READ_NAMESPACES_JSON: '["public/*"]',
      MBX_CACHE_MAX_BLOB_BYTES: '67108864',
      MBX_CACHE_OIDC_PROVIDERS_JSON:JSON.stringify(providers),
      ...bindings,
    },
  }] }));
}
before(async () => {
  oidcKeys=generateKeyPairSync('rsa',{modulusLength:2048});
  rotatedKeys=generateKeyPairSync('rsa',{modulusLength:2048});
  ecKeys=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  edKeys=generateKeyPairSync('ed25519');
  ec384Keys=generateKeyPairSync('ec',{namedCurve:'secp384r1'});
  mf=runtime();
  db = await mf.getD1Database('MBX_DB');
  bucket = await mf.getR2Bucket('MBX_BLOBS');
  const schema = await readFile(`${root}migrations/0001_init.sql`, 'utf8');
  for (const statement of schema.replace(/^--.*$/gm, '').split(';').filter(s => s.trim())) {
    await db.prepare(statement).run();
  }
});
after(async () => { await mf?.dispose(); });

function digest(bytes, algorithm = 'blake3') {
  bytes = Buffer.from(bytes);
  return { algorithm, hash: algorithm === 'blake3' ? Buffer.from(blake3(bytes)).toString('hex') : createHash('sha256').update(bytes).digest('hex'), size: bytes.length };
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
const encode = value => Buffer.from(JSON.stringify(canonical(value)));
const path = (kind, d) => `/v1/${kind}/${d.algorithm}/${d.hash}/${d.size}`;
function request(url, method = 'GET', body, headers = {}) {
  return mf.dispatchFetch(`https://cache.example${url}`, {
    method, body, ...(body instanceof ReadableStream ? {duplex:"half"} : {}),
    headers: { 'mbx-cache-protocol': '1', 'mbx-cache-namespace': 'test/project', authorization: 'Bearer test-token', ...headers },
  });
}
async function put(bytes, algorithm = 'blake3', headers = {}) {
  const d = digest(bytes, algorithm);
  const response = await request(path('blobs', d), 'PUT', bytes, { 'if-none-match': '*', ...headers });
  assert.ok([201,204].includes(response.status), `${response.status}: ${await response.text()}`);
  return d;
}
function pack(entries) {
  return Buffer.concat([Buffer.from('MBXPACK1'), ...entries.flatMap(([d, bytes]) => {
    const size = Buffer.alloc(8); size.writeBigUInt64BE(BigInt(d.size));
    return [Buffer.from([d.algorithm === 'blake3' ? 1 : 2]), Buffer.from(d.hash,'hex'), size, Buffer.from(bytes)];
  })]);
}
function packHeaders(entries) {
  return { 'content-type': packType, 'mbx-cache-pack-blobs': String(entries.length), 'mbx-cache-pack-bytes': String(entries.reduce((sum,[d]) => sum+d.size,0)) };
}
const task = () => ({ arch:'x86_64',args:[],command_inputs:[],dependency_keys:[],environment:{},kind:'task',os:'linux',outputs:['out'],phase:'normal',root:'.',run:['build'],shell:null,source_hash:'source',task:'build',tools:[],vars:{},version:1 });

test('capabilities advertise only supported features and encodings', async () => {
  const response = await request('/v1/capabilities');
  assert.equal(response.status,200);
  const c = await response.json();
  assert.deepEqual(c.compressors,['identity','zstd']);
  assert.equal(c.features.blob_pack_uploads,true);
  assert.equal(c.features.action_promises,false);
  assert.equal(c.limits.max_batch_items,512);
});

test('requires protocol, authorization, namespace and immutable preconditions', async () => {
  const d = digest('authorization'); const url = path('blobs',d);
  assert.equal((await request(url,'GET',undefined,{'mbx-cache-protocol':'2'})).status,426);
  assert.equal((await request(url,'GET',undefined,{authorization:''})).status,401);
  assert.equal((await request(url,'GET',undefined,{'mbx-cache-namespace':'test/../project'})).status,400);
  assert.equal((await request(url,'PUT','authorization',{'if-none-match':'*',authorization:'Bearer read-token'})).status,403);
  assert.equal((await request(url,'PUT','authorization')).status,412);
  assert.equal((await request(url,'GET',undefined,{'mbx-cache-namespace':'public/cache',authorization:''})).status,404);
  assert.equal((await request(url,'PUT','authorization',{'mbx-cache-namespace':'public/cache',authorization:''})).status,401);
});

test('streams BLAKE3, SHA256 and empty blobs; deduplicates concurrent uploads', async () => {
  for (const algorithm of ['blake3','sha256']) {
    for (const bytes of [Buffer.alloc(0),Buffer.alloc(3*1024*1024,73)]) {
      const d = await put(bytes,algorithm);
      const response = await request(path('blobs',d));
      assert.equal(response.status,200);
      assert.equal(response.headers.get('content-length'),String(bytes.length));
      assert.deepEqual(Buffer.from(await response.arrayBuffer()),bytes);
    }
  }
  const bytes=Buffer.alloc(256*1024,62),d=digest(bytes);
  const statuses=await Promise.all(Array.from({length:4},async()=> (await request(path('blobs',d),'PUT',bytes,{'if-none-match':'*'})).status));
  assert.equal(statuses.filter(s=>s===201).length,1);
  assert.equal(statuses.filter(s=>s===204).length,3);
});

test('bad hashes, sizes and unsupported encoding never gain namespace visibility', async () => {
  const bytes=Buffer.from('expected-content'),d=digest(bytes),url=path('blobs',d);
  for (const bad of [Buffer.alloc(bytes.length,0),bytes.subarray(1),Buffer.concat([bytes,Buffer.from('x')])]) {
    const response=await request(url,'PUT',bad,{'if-none-match':'*'});
    assert.ok([400,413].includes(response.status),`${response.status}: ${await response.text()}`);
    assert.equal((await request(url)).status,404);
  }
  assert.equal((await request(url,'PUT',bytes,{'if-none-match':'*','content-encoding':'gzip'})).status,415);
  await put(bytes);
  assert.equal((await request(url,'GET',undefined,{'mbx-cache-namespace':'test/other'})).status,404);
  const missing=await request('/v1/blobs:missing','POST',JSON.stringify({digests:[d]}),{'mbx-cache-namespace':'test/other'});
  assert.deepEqual((await missing.json()).missing,[d]);
});

test('streams blob packs in both directions, deduplicates members and isolates namespaces', async () => {
  const entries = [['pack-a','blake3'],['pack-b','sha256'],['','blake3']].map(([s,a])=>[digest(s,a),Buffer.from(s)]);
  const response=await request('/v1/blobs:pack-upload','POST',pack(entries),packHeaders(entries));
  assert.equal(response.status,200,await response.clone().text());
  const receipt=await response.json(); assert.equal(receipt.created+receipt.existing,3);
  const download=await request('/v1/blobs:pack','POST',JSON.stringify({digests:[...entries.map(([d])=>d),entries[0][0]]}));
  assert.equal(download.status,200,await download.clone().text());
  assert.equal(download.headers.get('mbx-cache-pack-blobs'),'3');
  assert.deepEqual(Buffer.from(await download.arrayBuffer()),pack(entries));
  const other=await request('/v1/blobs:pack','POST',JSON.stringify({digests:entries.map(([d])=>d)}),{'mbx-cache-namespace':'test/other'});
  assert.deepEqual(Buffer.from(await other.arrayBuffer()),Buffer.from('MBXPACK1'));
});

test('rejects corrupt and truncated packs while keeping earlier verified frames', async () => {
  const a=Buffer.from('good-prefix'),b=Buffer.from('bad-suffix'),entries=[[digest(a),a],[digest(b),Buffer.alloc(b.length)]];
  const response=await request('/v1/blobs:pack-upload','POST',pack(entries),packHeaders(entries));
  assert.equal(response.status,400,await response.clone().text());
  assert.equal((await request(path('blobs',entries[0][0]))).status,200);
  assert.equal((await request(path('blobs',entries[1][0]))).status,404);
  const truncated=await request('/v1/blobs:pack-upload','POST',pack(entries).subarray(0,30),packHeaders(entries));
  assert.equal(truncated.status,400);
});

test('validates action trees before immutable publication and supports batched reads', async () => {
  const action=await put(encode(task()));
  const file=digest('tree-file');
  const root=await put(encode({directories:[],files:[{digest:file,executable:false,mode:420,name:'out'}],symlinks:[],version:1}));
  const result={action,metadata:null,output_root:root,version:1};
  const url=path('action-results',action),headers={'if-none-match':'*'};
  assert.equal((await request(url,'PUT',JSON.stringify(result),headers)).status,422);
  await put('tree-file');
  let response=await request(url,'PUT',JSON.stringify(result),headers);
  assert.equal(response.status,201,await response.clone().text());
  assert.equal((await request(url,'PUT',JSON.stringify(result),headers)).status,204);
  assert.equal((await request(url,'PUT',JSON.stringify({...result,output_root:null}),headers)).status,409);
  assert.deepEqual(await (await request(url)).json(),result);
  const batch=await request('/v1/action-results:batch','POST',JSON.stringify({digests:[action,action]}));
  assert.deepEqual((await batch.json()).results,[result]);
  const other=await request('/v1/action-results:batch','POST',JSON.stringify({digests:[action]}),{'mbx-cache-namespace':'test/other'});
  assert.deepEqual((await other.json()).results,[]);
});

test('manifest updates use atomic ETag preconditions and canonical R2 bodies', async () => {
  const task='a'.repeat(64);
  const key=digest(encode({kind:'task_action_manifest',task,version:1}));
  const url=path('action-manifests',key),manifest={version:1,task,predictions:[]};
  assert.equal((await request(url,'PUT',JSON.stringify(manifest))).status,428);
  const created=await request(url,'PUT',JSON.stringify(manifest),{'if-none-match':'*'});
  assert.equal(created.status,201,await created.clone().text());
  const etag=created.headers.get('etag');
  const response=await request(url);
  assert.equal(response.headers.get('etag'),etag);
  assert.equal(await response.text(),encode(manifest).toString());
  assert.equal((await request(url,'PUT',JSON.stringify(manifest),{'if-none-match':'*'})).status,412);
  assert.equal((await request(url,'PUT',JSON.stringify(manifest),{'if-match':`"${'0'.repeat(64)}"`})).status,412);
  assert.equal((await request(url,'PUT',JSON.stringify(manifest),{'if-match':etag})).status,204);
  const row=await db.prepare('SELECT object_key FROM action_manifests').first();
  assert.equal(await (await bucket.get(row.object_key)).text(),encode(manifest).toString());
});


test('large manifest bodies stay in R2 and simultaneous updates cannot overwrite each other', async () => {
  const task='b'.repeat(64), key=digest(encode({kind:'task_action_manifest',task,version:1}));
  const url=path('action-manifests',key);
  const initial={version:1,task,predictions:[]};
  const created=await request(url,'PUT',encode(initial),{'if-none-match':'*'});
  assert.equal(created.status,201);
  const etag=created.headers.get('etag');
  const make = variant => ({version:1,task,predictions:Array.from({length:12},(_,i)=>({
    invocation:digest(`invocation-${i}`),action:digest(`action-${i}`),adapter:'rustc',
    payload:JSON.stringify({variant,data:'x'.repeat(180_000)}),
  }))});
  const a=encode(make('a')),b=encode(make('b'));
  assert.ok(a.length>2_000_000);
  const statuses=await Promise.all([a,b].map(async body=>(await request(url,'PUT',body,{'if-match':etag})).status));
  assert.deepEqual(statuses.sort(),[204,412]);
  const result=await request(url), body=Buffer.from(await result.arrayBuffer());
  assert.ok(body.equals(a)||body.equals(b));
  assert.equal(result.headers.get('etag'),`"${digest(body).hash}"`);
});

test('batch lookups exceed the D1 placeholder limit without exposing foreign blobs', async () => {
  const digests=Array.from({length:150},(_,i)=>digest(`batch-${i}`));
  const response=await request('/v1/blobs:missing','POST',JSON.stringify({digests}));
  assert.equal(response.status,200);
  assert.deepEqual((await response.json()).missing,digests);
  const oversized=await request('/v1/blobs:missing','POST',JSON.stringify({digests:Array.from({length:513},()=>digests[0])}));
  assert.equal(oversized.status,400);
});

test('pack framing survives headers and payloads split across request chunks', async () => {
  const bytes=Buffer.from('split-frame-payload'),entries=[[digest(bytes),bytes]],encoded=pack(entries);
  let offset=0;
  const body=new ReadableStream({pull(controller) {
    if (offset===encoded.length) return controller.close();
    const end=Math.min(encoded.length,offset+3);
    controller.enqueue(encoded.subarray(offset,end)); offset=end;
  }});
  const response=await request('/v1/blobs:pack-upload','POST',body,packHeaders(entries));
  assert.equal(response.status,200,await response.clone().text());
  assert.equal((await request(path('blobs',entries[0][0]))).status,200);
});

test('D1 transaction failure cannot publish an object or namespace membership', async () => {
  await db.prepare("CREATE TRIGGER refuse_test_membership BEFORE INSERT ON namespace_blobs WHEN NEW.namespace='test/failure' BEGIN SELECT RAISE(ABORT,'injected failure'); END").run();
  const bytes=Buffer.from('database-failure-blob'),d=digest(bytes);
  const response=await request(path('blobs',d),'PUT',bytes,{'if-none-match':'*','mbx-cache-namespace':'test/failure'});
  assert.equal(response.status,500);
  assert.equal((await request(path('blobs',d),'GET',undefined,{'mbx-cache-namespace':'test/failure'})).status,404);
  const key=`${d.algorithm}/${d.hash}/${d.size}`;
  assert.equal(await db.prepare('SELECT * FROM blob_objects WHERE blob_key=?').bind(key).first(),null);
  await db.prepare('DROP TRIGGER refuse_test_membership').run();
  await put(bytes,'blake3',{'mbx-cache-namespace':'test/failure'});
});

test('scheduled cleanup persists its cursor and preserves referenced objects', async () => {
  const worker=await mf.getWorker();
  await worker.scheduled({cron:'17 * * * *'});
  const row=await db.prepare("SELECT * FROM maintenance WHERE name='orphans'").first();
  assert.ok(row);
  const d=await put('survives-maintenance');
  await worker.scheduled({cron:'17 * * * *'});
  assert.equal((await request(path('blobs',d))).status,200);
});

test('cross-namespace deduplication still requires proof of blob content', async () => {
  const bytes=Buffer.from('private-cross-namespace-content'),d=await put(bytes);
  const key=`${d.algorithm}/${d.hash}/${d.size}`;
  const before=await db.prepare('SELECT object_key FROM blob_objects WHERE blob_key=?').bind(key).first();
  const headers={'mbx-cache-namespace':'test/second','if-none-match':'*'};
  const invalid=await request(path('blobs',d),'PUT',Buffer.alloc(bytes.length),headers);
  assert.equal(invalid.status,400);
  assert.equal((await request(path('blobs',d),'GET',undefined,headers)).status,404);
  const upload=await request(path('blobs',d),'PUT',bytes,headers);
  assert.equal(upload.status,204);
  assert.equal(await (await request(path('blobs',d),'GET',undefined,headers)).text(),bytes.toString());
  const after=await db.prepare('SELECT object_key FROM blob_objects WHERE blob_key=?').bind(key).first();
  assert.deepEqual(after,before);
});

function compressed(bytes, checksum=true) {
  return zstdCompressSync(bytes,{params:{[zconst.ZSTD_c_contentSizeFlag]:0,[zconst.ZSTD_c_checksumFlag]:Number(checksum)}});
}
function streaming(bytes, n=3) {
  let offset=0;
  return new ReadableStream({pull(controller) {
    if(offset===bytes.length) return controller.close();
    const end=Math.min(bytes.length,offset+n);controller.enqueue(bytes.subarray(offset,end));offset=end;
  }});
}
test('zstd uploads stream BLAKE3/SHA256 bodies, concatenated frames and skippable frames', async () => {
  for(const algorithm of ['blake3','sha256']) {
    for(const bytes of [Buffer.alloc(0),Buffer.alloc(3*1024*1024,80)]) {
      const d=digest(bytes,algorithm),encoded=compressed(bytes);
      const response=await request(path('blobs',d),'PUT',streaming(encoded,7),{'if-none-match':'*','content-encoding':'zstd'});
      assert.ok([201,204].includes(response.status),`${response.status}: ${await response.text()}`);
      assert.deepEqual(Buffer.from(await (await request(path('blobs',d))).arrayBuffer()),bytes);
    }
  }
  const a=Buffer.from('multi-frame-a'),b=Buffer.from('multi-frame-b');
  const skip=Buffer.from([0x50,0x2a,0x4d,0x18,3,0,0,0,1,2,3]);
  const bytes=Buffer.concat([a,b]),d=digest(bytes);
  const encoded=Buffer.concat([skip,compressed(a),compressed(b),skip]);
  assert.equal((await request(path('blobs',d),'PUT',streaming(encoded,1),{'if-none-match':'*','content-encoding':'zstd'})).status,201);
});

test('corrupt, truncated, oversized-window and expanding zstd uploads never publish', async () => {
  const bytes=Buffer.from('zstd-invalid-input-target'),d=digest(bytes),url=path('blobs',d);
  const encoded=compressed(bytes);
  const badChecksum=Buffer.from(encoded);badChecksum[badChecksum.length-1]^=0xff;
  for(const bad of [encoded.subarray(0,encoded.length-1),badChecksum,Buffer.concat([encoded,Buffer.from('junk')]),
    Buffer.from([0x28,0xb5,0x2f,0xfd,0,0xf8])]) {
    const response=await request(url,'PUT',streaming(bad,2),{'if-none-match':'*','content-encoding':'zstd'});
    assert.equal(response.status,400,await response.clone().text());
    assert.equal((await request(url)).status,404);
  }
  const bomb=await request(url,'PUT',compressed(Buffer.alloc(3*1024*1024)),{'if-none-match':'*','content-encoding':'zstd'});
  assert.equal(bomb.status,413,await bomb.clone().text());
  assert.equal((await request(url)).status,404);
});

test('zstd blob packs decode incrementally and preserve per-frame verification', async () => {
  const bytes=Buffer.from('compressed-pack-member');
  const entries=[[digest(bytes),bytes],[digest(''),Buffer.alloc(0)]];
  const response=await request('/v1/blobs:pack-upload','POST',streaming(compressed(pack(entries)),2),{...packHeaders(entries),'content-encoding':'zstd'});
  assert.equal(response.status,200,await response.clone().text());
  assert.equal((await request(path('blobs',entries[0][0]))).status,200);
  const corrupt=[[digest('bad-compressed-member'),Buffer.from('wrong-compressed-data')]];
  const bad=await request('/v1/blobs:pack-upload','POST',compressed(pack(corrupt)),{...packHeaders(corrupt),'content-encoding':'zstd'});
  assert.ok([400,413].includes(bad.status));
  assert.equal((await request(path('blobs',corrupt[0][0]))).status,404);
});

test('OIDC discovers and caches keys across concurrent requests and supports RSA, EC and Ed25519', async () => {
  const d=digest('oidc-missing'),url=path('blobs',d);
  const token=jwt();
  const statuses=await Promise.all(Array.from({length:4},async()=> (await request(url,'GET',undefined,{authorization:`Bearer ${token}`})).status));
  assert.deepEqual(statuses,[404,404,404,404]);
  assert.equal(outboundCounts.get('https://issuer.test/.well-known/openid-configuration'),1);
  assert.equal(outboundCounts.get('https://issuer.test/keys'),1);
  for(const [algorithm,kid,key] of [['ES256','ec-key',ecKeys.privateKey],['ES384','ec384-key',ec384Keys.privateKey],['EdDSA','ed-key',edKeys.privateKey],
    ...['RS384','RS512','PS256','PS384','PS512'].map(alg=>[alg,`${alg}-key`,oidcKeys.privateKey])]) {
    assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${jwt({}, {algorithm,kid,key})}`})).status,404);
  }
  const bytes=Buffer.from('oidc-upload'),upload=await request(path('blobs',digest(bytes)),'PUT',bytes,{'if-none-match':'*',authorization:`Bearer ${token}`});
  assert.equal(upload.status,201,await upload.clone().text());
});

test('OIDC verifies signatures, issuer, audience, expiry, subject, not-before and JWK constraints', async () => {
  const now=Math.floor(Date.now()/1000),url=path('blobs',digest('oidc-invalid'));
  const invalid=[jwt({aud:'wrong'}),jwt({iss:'https://untrusted.test'}),jwt({exp:now-300}),jwt({nbf:now+300}),
    jwt({sub:undefined}),jwt({exp:undefined}),jwt({aud:undefined}),jwt({}, {algorithm:'HS256'}),
    jwt({}, {key:rotatedKeys.privateKey}),jwt({}, {kid:'bad-use'}),jwt({}, {kid:'bad-alg'}),jwt({}, {kid:'bad-ops'}),
    jwt({}, {header:{crit:['custom']}})];
  for(const token of invalid) {
    const response=await request(url,'GET',undefined,{authorization:`Bearer ${token}`});
    assert.equal(response.status,401,await response.clone().text());
  }
  const valid=jwt({aud:['another-audience','https://cache.example']});
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${valid}`})).status,404);
});

test('OIDC claim grants keep pull requests read-only and require exact claim types', async () => {
  const bytes=Buffer.from('oidc-pr-output'),url=path('blobs',digest(bytes));
  const pr=jwt({event_name:'pull_request'});
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${pr}`})).status,404);
  assert.equal((await request(url,'PUT',bytes,{'if-none-match':'*',authorization:`Bearer ${pr}`})).status,403);
  for(const claims of [{repository_owner_id:123},{repository_owner_id:'wrong'},{repository:'another/project'}]) {
    assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${jwt(claims)}`})).status,403);
  }
  const grouped=jwt({repository:undefined,groups:['other','build'],trusted:true,level:2});
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${grouped}`})).status,404);
  assert.equal((await request(url,'PUT',bytes,{'if-none-match':'*',authorization:`Bearer ${grouped}`})).status,403);
});

test('OIDC explicit JWKS skips discovery; mismatched discovery issuers fail closed', async () => {
  const url=path('blobs',digest('oidc-direct'));
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${jwt({iss:'https://direct.test'})}`})).status,404);
  assert.equal(outboundCounts.get('https://direct.test/.well-known/openid-configuration'),undefined);
  assert.equal(outboundCounts.get('https://direct.test/keys'),1);
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${jwt({iss:'https://mismatch.test'})}`})).status,401);
  assert.equal(outboundCounts.get('https://mismatch.test/keys'),undefined);
});

test('OIDC throttles unknown kids, rotates keys, and retains known keys on refresh failure', {timeout:40_000}, async () => {
  const url=path('blobs',digest('oidc-rotation'));
  const fallback=jwt({iss:'https://fallback.test'});
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${fallback}`})).status,404);
  const before=outboundCounts.get('https://issuer.test/keys');
  for(let i=0;i<4;i++) {
    const unknown=jwt({}, {kid:`unknown-${i}`});
    assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${unknown}`})).status,401);
  }
  assert.equal(outboundCounts.get('https://issuer.test/keys'),before);
  await delay(31_000);
  failFallback=true;
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${fallback}`})).status,404);
  rotated=true;
  const token=jwt({}, {kid:'rotated-key',key:rotatedKeys.privateKey});
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${token}`})).status,404);
  assert.equal(outboundCounts.get('https://issuer.test/keys'),before+1);
  assert.equal((await request(url,'GET',undefined,{authorization:`Bearer ${jwt()}`})).status,401);
});

test('OIDC rejects empty claim rules, empty audiences, duplicate issuers and symmetric-only configuration', async () => {
  const base=providers[0];
  for(const configs of [
    [{...base,rules:[{claims:{},read:['*'],write:['*']}]}],
    [{...base,audiences:[]}], [base,base], [{...base,algorithms:['HS256']}],
  ]) {
    const fixture=runtime({MBX_CACHE_OIDC_PROVIDERS_JSON:JSON.stringify(configs)});
    try {
      const response=await fixture.dispatchFetch(`https://cache.example${path('blobs',digest('config'))}`,{
        headers:{'mbx-cache-protocol':'1','mbx-cache-namespace':'test/project',authorization:`Bearer ${jwt()}`},
      });
      assert.equal(response.status,500,await response.clone().text());
    } finally {await fixture.dispose();}
  }
});

test('encoded-byte limits also bound zstd skippable frames that produce no output', async () => {
  const fixture=runtime({MBX_CACHE_MAX_BLOB_BYTES:'1024'});
  try {
    const header=Buffer.from([0x50,0x2a,0x4d,0x18,0,8,0,0]);
    const response=await fixture.dispatchFetch(`https://cache.example${path('blobs',digest(''))}`,{
      method:'PUT',body:Buffer.concat([header,Buffer.alloc(2048)]),
      headers:{'mbx-cache-protocol':'1','mbx-cache-namespace':'test/project',authorization:'Bearer test-token',
        'if-none-match':'*','content-encoding':'zstd'},
    });
    assert.equal(response.status,413,await response.clone().text());
    assert.equal((await (await fixture.getR2Bucket('MBX_BLOBS')).list()).objects.length,0);
  } finally {await fixture.dispose();}
});
