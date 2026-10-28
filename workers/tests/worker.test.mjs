import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { blake3 } from '@noble/hashes/blake3.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const packType = 'application/vnd.mbx.cache-blob-pack.v1';
let mf, db, bucket;
before(async () => {
  mf = new Miniflare(convertV4MiniflareOptions({ workers: [{
    name: "mbx-cache",
    modulesRoot: `${root}build`,
    modules: [
      {type:'ESModule',path:`${root}build/index.js`},
      {type:'CompiledWasm',path:`${root}build/index_bg.wasm`},
    ],
    compatibilityDate: '2026-10-28',
    d1Databases: ['MBX_DB'], r2Buckets: ['MBX_BLOBS'],
    bindings: {
      MBX_CACHE_TOKENS_JSON: JSON.stringify([
        { token: 'test-token', read: ['test/*'], write: ['test/*'] },
        { token: 'read-token', read: ['test/*'], write: [] },
      ]),
      MBX_CACHE_ANONYMOUS_READ_NAMESPACES_JSON: '["public/*"]',
      MBX_CACHE_MAX_BLOB_BYTES: '67108864',
    },
  }] }));
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
  assert.deepEqual(c.compressors,['identity']);
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
  assert.equal((await request(url,'PUT',bytes,{'if-none-match':'*','content-encoding':'zstd'})).status,415);
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
