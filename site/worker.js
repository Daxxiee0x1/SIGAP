// Runs the SIGAP verifier (Go compiled to WebAssembly) off the main thread, so the page
// stays responsive while bundles are verified. Messages: { id, fn, args } -> { id, result | error }.
"use strict";
importScripts("wasm_exec.js");

const ready = (async () => {
  const go = new Go();
  let result;
  try {
    result = await WebAssembly.instantiateStreaming(fetch("sigap.wasm"), go.importObject);
  } catch (_) {
    const r = await fetch("sigap.wasm");
    if (!r.ok) throw new Error("sigap.wasm: HTTP " + r.status);
    result = await WebAssembly.instantiate(await r.arrayBuffer(), go.importObject);
  }
  const started = new Promise((resolve) => { self.onSigapReady = resolve; });
  go.run(result.instance);
  await started;
  return self.sigap.version;
})();

self.onmessage = async (e) => {
  const { id, fn, args } = e.data;
  try {
    const version = await ready;
    if (fn === "init") return self.postMessage({ id, result: version });
    if (!["verify", "entries", "edit"].includes(fn)) throw new Error("fungsi tidak dikenal: " + fn);
    const out = self.sigap[fn](...args);
    if (out instanceof Error) throw out;
    self.postMessage({ id, result: out });
  } catch (err) {
    self.postMessage({ id, error: String((err && err.message) || err) });
  }
};
