// SIGAP verifier online. The verifier is the Go code in internal/verify compiled to
// WebAssembly (sigap.wasm) and runs in worker.js. Bundles are untrusted input: everything
// derived from them is inserted with textContent, never as HTML.
"use strict";
(() => {
  const NS = "http://www.w3.org/2000/svg";
  const SAMPLES = {
    "00_asli.zip": "Bundle asli dari node sensor-01, tidak diubah",
    "01_flip_byte.zip": "1 bit di daftar proses dibalik",
    "02_add_unlisted.zip": "Berkas tambahan yang tidak tercantum di manifest",
    "03_remove_listed.zip": "Log sistem dihapus dari zip",
    "04_edit_manifest.zip": "Nomor urut di manifest diubah",
    "05_swap_signature.zip": "Tanda tangan diganti tanda tangan palsu",
    "06_kunci_asing.zip": "Ditandatangani kunci sah yang tidak terdaftar",
    "07a_zip_slip.zip": "Entri berjalur ../../etc/cron.d/backdoor",
    "07b_symlink.zip": "Entri symlink ke /etc/shadow",
    "08_decompression_bomb.zip": "Entri 110 MB yang memadat jadi sangat kecil",
  };
  const EXPLAIN = {
    VALID: "Tanda tangan sah dari kunci di trust store dan semua hash artefak cocok. Bukti utuh sejak ditandatangani di node.",
    TAMPERED: "Ada byte yang berubah atau berkas yang diselipkan setelah bundle ditandatangani. Bukti harus dikarantina dan diminta ulang dari node.",
    INCOMPLETE: "Berkas yang tercantum di manifest hilang dari bundle. Minta bundle utuh dari outbox node.",
    UNTRUSTED_SIGNER: "Tanda tangan dibuat dengan kunci yang tidak ada di trust store, sudah dicabut, atau kedaluwarsa. Kunci publik hanya diambil dari trust store lokal, tidak pernah dari bundle.",
    MALFORMED: "Bundle ditolak sebelum isinya dibaca: bukan zip yang sah, nama berkas berbahaya, symlink, atau indikasi bom dekompresi. Jangan diekstrak.",
  };
  const ICON = { VALID: "i-ok", TAMPERED: "i-x", INCOMPLETE: "i-missing", UNTRUSTED_SIGNER: "i-untrusted", MALFORMED: "i-malformed" };
  const ORIGINAL = "00_asli.zip";
  const FOREIGN_FILE = "artifacts/catatan_penyerang.txt";
  const MAX_UPLOAD = 20 * 1024 * 1024;

  const $ = (id) => document.getElementById(id);
  const state = { ready: false, busy: false, version: "", trust: "", samples: [], cache: new Map(), active: null, original: null, working: null, originalEntries: [], workingEntries: [], current: null, upload: null, ownTrust: null };

  function el(tag, props = {}, ...children) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) n.append(c instanceof Node ? c : String(c));
    return n;
  }
  // Copies the sprite symbol's shapes instead of using <use>, so results that are
  // re-rendered often do not create SVG instance shadow trees each time.
  function icon(id, cls = "ico") {
    const svg = document.createElementNS(NS, "svg");
    const sym = document.getElementById(id);
    svg.setAttribute("class", cls);
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("viewBox", sym ? sym.getAttribute("viewBox") : "0 0 48 48");
    if (sym) for (const c of sym.children) svg.append(c.cloneNode(true));
    return svg;
  }
  const stamp = (status) => el("span", { class: "st " + (status || "pending"), text: status || "belum" });
  const fmtSize = (n) => (n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB");

  // ---------- verifier (in worker.js) ----------
  let worker = null;
  let seq = 0;
  const calls = new Map();
  function call(fn, ...args) {
    return new Promise((resolve, reject) => {
      const id = ++seq;
      calls.set(id, { resolve, reject });
      worker.postMessage({ id, fn, args });
    });
  }
  async function verify(bytes, trustText) {
    const res = JSON.parse(await call("verify", bytes, trustText));
    if (res.error) throw new Error(res.error);
    return res;
  }
  async function entries(bytes) {
    const res = JSON.parse(await call("entries", bytes));
    if (res && res.error) throw new Error(res.error);
    return res;
  }
  const edit = (bytes, op, name, content) => call("edit", bytes, op, name, content);

  function renderResult(box, res, opts = {}) {
    const reasons = res.reasons || [];
    const m = res.manifest;
    const verdict = el("div", { class: "verdict " + res.status },
      icon(ICON[res.status] || "i-x"),
      el("div", { class: "verdict-text" },
        el("span", { class: "verdict-status", text: res.status }),
        el("span", { class: "verdict-sub", text: `${opts.name || "bundle"} · exit ${res.exit_code} · ${res.duration_us} µs` })));

    const body = el("div", { class: "result-body" });
    if (opts.expected) {
      const same = opts.expected === res.status;
      body.append(el("p", { class: "summary " + (same ? "ok" : "bad"), text: same ? `Sesuai harapan (${opts.expected})` : `Tidak sesuai harapan (${opts.expected})` }));
    }
    body.append(el("p", { class: "explain", text: EXPLAIN[res.status] || "" }));
    if (reasons.length) body.append(el("ul", { class: "reasons" }, reasons.map((r) => el("li", { text: r }))));

    const kv = el("dl", { class: "kv" });
    const row = (k, v) => kv.append(el("dt", { text: k }), el("dd", { text: v || "-" }));
    row("SHA-256 bundle", res.bundle_sha256);
    row("Kunci penanda tangan", res.key_id);
    if (m) {
      row("Node", m.node_id);
      row("Bundle ID", m.bundle_id);
      row("Pemicu", m.trigger);
      row("Urutan", String(m.sequence));
      row("Dikumpulkan", `${m.collected_at} (dilaporkan node)`);
    }
    body.append(kv);

    if (m && Array.isArray(m.artifacts)) {
      const bad = new Set(reasons.filter((r) => r.startsWith("hash/ukuran tidak cocok: ")).map((r) => r.slice(25)));
      const miss = new Set(reasons.filter((r) => r.startsWith("berkas di manifest tidak ada di zip: ")).map((r) => r.slice(37)));
      const rows = m.artifacts.map((a) => el("tr", { class: bad.has(a.path) ? "bad-row" : miss.has(a.path) ? "miss-row" : null },
        el("td", { text: a.path.replace("artifacts/", "") }),
        el("td", { text: fmtSize(a.size_bytes) }),
        el("td", { text: String(a.redactions) }),
        el("td", { text: a.sha256.slice(0, 12) + "…", title: a.sha256 })));
      body.append(el("div", { class: "table-scroll" }, el("table", { class: "spec arts" },
        el("caption", { class: "col-title", text: "Artefak menurut manifest bertanda tangan" }),
        el("thead", {}, el("tr", {}, ["Berkas", "Ukuran", "Redaksi", "SHA-256"].map((h) => el("th", { scope: "col", text: h })))),
        el("tbody", {}, rows))));
    } else if (res.status !== "VALID") {
      body.append(el("p", { class: "hint", text: "Isi manifest tidak ditampilkan. Verifier baru membaca manifest setelah tanda tangannya terbukti sah dari kunci tepercaya." }));
    }
    if (opts.download) body.append(el("div", { class: "result-actions" }, opts.download));
    box.replaceChildren(verdict, body);
  }
  function renderMessage(box, text, isError) {
    box.replaceChildren(el("p", { class: "placeholder" + (isError ? " hint err" : ""), text }));
  }

  // ---------- data ----------
  async function fetchText(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    return r.text();
  }
  async function sampleBytes(name) {
    if (!state.cache.has(name)) {
      const r = await fetch("samples/bundle/" + encodeURIComponent(name));
      if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
      state.cache.set(name, new Uint8Array(await r.arrayBuffer()));
    }
    return state.cache.get(name);
  }
  async function loadSamples() {
    const [list, trust] = await Promise.all([fetchText("samples/bundle/harapan.txt"), fetchText("samples/trust_store.json")]);
    state.trust = trust;
    state.samples = list.split("\n").map((l) => l.trim().split(/\s+/)).filter((p) => p.length === 2).map(([name, expected]) => ({ name, expected, result: null }));
  }

  // ---------- 01 samples ----------
  function drawSamples() {
    const tbody = $("sample-rows");
    tbody.replaceChildren(...state.samples.map((s) => {
      const res = s.result ? [stamp(s.result.status), el("span", { class: "match " + (s.result.status === s.expected ? "yes" : "no"), text: s.result.status === s.expected ? "cocok" : "BEDA" })] : [stamp(null)];
      return el("tr", { class: state.active === s.name ? "active" : null, onclick: () => showSample(s) },
        el("td", {}, el("button", { class: "file", type: "button", text: s.name, "aria-label": `Verifikasi ${s.name}`, onclick: (e) => { e.stopPropagation(); showSample(s); } })),
        el("td", { class: "desc", text: SAMPLES[s.name] || "" }),
        el("td", {}, stamp(s.expected)),
        el("td", {}, res));
    }));
  }
  async function runSample(s) {
    s.result = await verify(await sampleBytes(s.name), state.trust);
    return s.result;
  }
  async function showSample(s) {
    if (!state.ready) return;
    state.active = s.name;
    try {
      await runSample(s);
      drawSamples();
      renderResult($("result-samples"), s.result, {
        name: s.name, expected: s.expected,
        download: el("a", { href: "samples/bundle/" + encodeURIComponent(s.name), download: s.name, text: "Unduh bundle ini" }),
      });
    } catch (err) {
      renderMessage($("result-samples"), "Gagal memverifikasi: " + err.message, true);
    }
  }
  async function verifyAll() {
    const btn = $("verify-all");
    btn.disabled = true;
    try {
      for (const s of state.samples) await runSample(s);
      const ok = state.samples.filter((s) => s.result.status === s.expected).length;
      const sum = $("summary");
      sum.textContent = `${ok} dari ${state.samples.length} hasil sesuai harapan`;
      sum.className = "summary " + (ok === state.samples.length ? "ok" : "bad");
      const focus = state.samples.find((s) => s.name === state.active) || state.samples.find((s) => s.name === "01_flip_byte.zip") || state.samples[0];
      await showSample(focus);
    } catch (err) {
      renderMessage($("result-samples"), "Gagal memverifikasi: " + err.message, true);
    } finally {
      btn.disabled = false;
    }
  }

  // ---------- 02 editor ----------
  const textOf = (list, name) => (list.find((e) => e.name === name) || {}).text;
  function editMsg(text, isError) {
    const m = $("edit-msg");
    m.textContent = text || "";
    m.className = "hint" + (isError ? " err" : "");
  }
  function fileStatus(name) {
    const inOrig = state.originalEntries.some((e) => e.name === name);
    const inWork = state.workingEntries.some((e) => e.name === name);
    if (!inWork) return "removed";
    if (!inOrig) return "added";
    return textOf(state.originalEntries, name) === textOf(state.workingEntries, name) ? "" : "changed";
  }
  const STATUS_LABEL = { changed: "diubah", added: "asing", removed: "dihapus" };
  function drawFiles() {
    const names = [...new Set([...state.originalEntries, ...state.workingEntries].map((e) => e.name))];
    const items = [];
    let grouped = false;
    for (const name of names) {
      const st = fileStatus(name);
      const inDir = name.startsWith("artifacts/");
      if (inDir && !grouped) {
        items.push(el("li", { class: "group", text: "artifacts/" }));
        grouped = true;
      }
      const cls = [st === "removed" ? "gone" : "", inDir ? "indent" : ""].join(" ").trim() || null;
      items.push(el("li", { class: cls },
        el("button", { type: "button", title: name, "aria-label": name + (st ? ` (${STATUS_LABEL[st]})` : ""), "aria-current": state.current === name ? "true" : "false", onclick: () => selectFile(name) },
          el("span", { text: inDir ? name.slice(10) : name }),
          st ? el("span", { class: "tag " + st, text: STATUS_LABEL[st] }) : null)));
    }
    $("file-list").replaceChildren(...items);
  }
  function showCurrent() {
    const ta = $("file-text");
    const name = state.current;
    $("file-label").textContent = name || "Pilih berkas";
    const removed = name && fileStatus(name) === "removed";
    ta.disabled = !name || removed;
    ta.value = removed ? "(berkas ini sudah dihapus dari bundle)" : textOf(state.workingEntries, name) || "";
    $("file-state").textContent = "";
    $("edit-remove").disabled = !name || removed;
  }
  async function applyPending() {
    const name = state.current;
    if (!name || fileStatus(name) === "removed") return false;
    const text = $("file-text").value;
    if (text === textOf(state.workingEntries, name)) return false;
    state.working = await edit(state.working, "replace", name, text);
    state.workingEntries = await entries(state.working);
    return true;
  }
  async function selectFile(name) {
    if (state.busy) return;
    state.busy = true;
    try { await applyPending(); } catch (err) { editMsg(err.message, true); }
    state.busy = false;
    state.current = name;
    drawFiles();
    showCurrent();
  }
  async function verifyWorking() {
    renderResult($("result-edit"), await verify(state.working, state.trust), {
      name: "bundle ubahan",
      download: el("button", { class: "btn ghost", type: "button", text: "Unduh bundle ini", onclick: downloadWorking }),
    });
  }
  // Editor actions run one at a time; a second click while one is in flight is ignored.
  function guarded(fn) {
    return async () => {
      if (state.busy) return;
      state.busy = true;
      try { editMsg(""); await fn(); } catch (err) { editMsg(err.message, true); } finally { state.busy = false; }
    };
  }
  function downloadWorking() {
    const url = URL.createObjectURL(new Blob([state.working], { type: "application/zip" }));
    const a = el("a", { href: url, download: "00_asli-diubah.zip" });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function setupEditor() {
    state.original = await sampleBytes(ORIGINAL);
    state.working = state.original;
    state.originalEntries = await entries(state.original);
    state.workingEntries = state.originalEntries;
    state.current = "artifacts/process_list.txt";
    drawFiles();
    showCurrent();
    $("file-text").addEventListener("input", () => {
      const dirty = $("file-text").value !== textOf(state.workingEntries, state.current);
      $("file-state").textContent = dirty ? "belum diverifikasi" : "";
    });
    $("edit-verify").addEventListener("click", guarded(async () => {
      await applyPending();
      drawFiles();
      showCurrent();
      await verifyWorking();
    }));
    $("edit-remove").addEventListener("click", guarded(async () => {
      await applyPending();
      state.working = await edit(state.working, "remove", state.current, "");
      state.workingEntries = await entries(state.working);
      editMsg(`${state.current} dihapus dari bundle.`);
      drawFiles();
      showCurrent();
      await verifyWorking();
    }));
    $("edit-add").addEventListener("click", guarded(async () => {
      await applyPending();
      if (state.workingEntries.some((e) => e.name === FOREIGN_FILE)) {
        state.current = FOREIGN_FILE;
      } else {
        state.working = await edit(state.working, "add", FOREIGN_FILE, "berkas ini diselipkan setelah bundle ditandatangani\n");
        state.workingEntries = await entries(state.working);
        state.current = FOREIGN_FILE;
        editMsg(`${FOREIGN_FILE} diselipkan ke bundle.`);
      }
      drawFiles();
      showCurrent();
      await verifyWorking();
    }));
    $("edit-reset").addEventListener("click", guarded(async () => {
      state.working = state.original;
      state.workingEntries = state.originalEntries;
      state.current = "artifacts/process_list.txt";
      drawFiles();
      showCurrent();
      renderMessage($("result-edit"), "Bundle dikembalikan ke versi asli.");
    }));
    $("edit-download").addEventListener("click", guarded(async () => { await applyPending(); drawFiles(); downloadWorking(); }));
  }

  // ---------- 03 upload ----------
  function trustForUpload() {
    const own = document.querySelector('input[name="trust"]:checked').value === "own";
    return own ? state.ownTrust : state.trust;
  }
  async function verifyUpload() {
    const box = $("result-upload");
    if (!state.upload) return;
    const trust = trustForUpload();
    if (!trust) return renderMessage(box, "Pilih file trust_store.json Anda terlebih dahulu.", true);
    try {
      renderResult(box, await verify(state.upload.bytes, trust), { name: state.upload.name });
    } catch (err) {
      renderMessage(box, err.message, true);
    }
  }
  async function takeBundle(file) {
    if (!file) return;
    $("drop-name").textContent = `${file.name} · ${fmtSize(file.size)}`;
    if (file.size > MAX_UPLOAD) {
      state.upload = null;
      return renderMessage($("result-upload"), "File lebih besar dari 20 MB, batas ukuran bundle SIGAP.", true);
    }
    state.upload = { name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) };
    verifyUpload();
  }
  function setupUpload() {
    const drop = $("drop");
    $("upload-bundle").addEventListener("change", (e) => takeBundle(e.target.files[0]));
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); if (state.ready) takeBundle(e.dataTransfer.files[0]); });
    document.querySelectorAll('input[name="trust"]').forEach((r) => r.addEventListener("change", () => {
      $("upload-trust").disabled = document.querySelector('input[name="trust"]:checked').value !== "own";
      verifyUpload();
    }));
    $("upload-trust").addEventListener("change", async (e) => {
      const f = e.target.files[0];
      state.ownTrust = f ? await f.text() : null;
      verifyUpload();
    });
  }

  // ---------- boot ----------
  function setEngine(cls, text) {
    $("engine").className = "engine " + cls;
    $("engine-text").textContent = text;
  }
  function fail(err) {
    setEngine("failed", "Verifier gagal dimuat");
    const msg = "Verifier tidak dapat dimuat di browser ini (" + (err && err.message ? err.message : err) + "). Gunakan browser terbaru, atau coba kit juri offline dari halaman Releases.";
    ["result-samples", "result-edit", "result-upload"].forEach((id) => renderMessage($(id), msg, true));
  }
  async function startWorker() {
    if (typeof WebAssembly !== "object" || typeof Worker !== "function") throw new Error("WebAssembly atau Web Worker tidak didukung");
    worker = new Worker("worker.js");
    worker.onmessage = (e) => {
      const { id, result, error } = e.data;
      const c = calls.get(id);
      if (!c) return;
      calls.delete(id);
      if (error) c.reject(new Error(error));
      else c.resolve(result);
    };
    const failed = new Promise((_, reject) => {
      worker.onerror = (e) => reject(new Error(e.message || "worker gagal dimuat"));
    });
    state.version = await Promise.race([call("init"), failed]);
  }

  async function boot() {
    $("verify-all").addEventListener("click", verifyAll);
    setupUpload();
    try {
      await Promise.all([startWorker(), loadSamples()]);
    } catch (err) {
      return fail(err);
    }
    state.ready = true;
    setEngine("ready", `Verifier siap · sigap ${state.version} · WebAssembly`);
    drawSamples();
    ["verify-all", "edit-verify", "edit-add", "edit-reset", "edit-download", "upload-bundle"].forEach((id) => { $(id).disabled = false; });
    try {
      await setupEditor();
    } catch (err) {
      editMsg("Bundle contoh gagal dimuat: " + err.message, true);
    }
  }
  document.addEventListener("DOMContentLoaded", boot);
})();
