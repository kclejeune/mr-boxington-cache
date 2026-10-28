// Platform binding only. Both entrypoints execute Rust/WASM; policy and routing live in Rust.
import RustWorker from './build/index.js';
export default RustWorker;
export class CachedStore extends RustWorker {
  fetch(request) { return super.cached_read(request, this.env, this.ctx); }
}
