// Test-only entrypoint: observe actual binding calls, including transient PUT/DELETE churn.
// Production entry.js never imports this module.
import RustWorker from '../build/index.js';
export { CachedStore } from '../entry.js';

const operations = { put: 0, delete: 0 };
let failAfterPublication = false;
export default class extends RustWorker {
  constructor(ctx, env) {
    const bucket = new Proxy(env.MBX_BLOBS, {
      get(target, name) {
        const value = Reflect.get(target, name, target);
        if (name === 'constructor' || typeof value !== 'function') return value;
        return (...args) => {
          if (Object.hasOwn(operations, name)) operations[name]++;
          return value.apply(target, args);
        };
      },
    });
    const database = new Proxy(env.MBX_DB, {
      get(target, name) {
        if (name === 'withSession') return (...args) => {
          const session = target.withSession(...args);
          return new Proxy(session, {
            get(target, name) {
              if (name === 'batch') return async (...args) => {
                const result = await target.batch(...args);
                if (failAfterPublication) throw new Error('simulated lost D1 response after commit');
                return result;
              };
              const value = Reflect.get(target, name, target);
              return typeof value === 'function' && name !== 'constructor' ? value.bind(target) : value;
            },
          });
        };
        const value = Reflect.get(target, name, target);
        return typeof value === 'function' && name !== 'constructor' ? value.bind(target) : value;
      },
    });
    super(ctx, { ...env, MBX_BLOBS: bucket, MBX_DB: database });
  }
  fetch(request) {
    if (new URL(request.url).pathname === '/__test/r2-operations') {
      return Response.json(operations);
    }
    if (new URL(request.url).pathname === '/__test/fail-after-publication') {
      failAfterPublication = true;
      return new Response(null, { status: 204 });
    }
    return super.fetch(request);
  }
}
