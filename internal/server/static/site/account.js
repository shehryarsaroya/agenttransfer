// AgentTransfer account page: the browser's view of the shared drive.
// Uploads go straight to object storage (presigned single PUT, or parallel
// multipart parts for large files); the server verifies every byte's sha256
// before the file appears in the drive.
(function () {
  "use strict";
  const drive = document.getElementById("drive");
  if (!drive) return;
  const csrf = drive.dataset.csrf;
  const remote = drive.dataset.remote === "true";
  const tbody = document.querySelector("#files tbody");
  const progress = document.getElementById("progress");
  const pick = document.getElementById("filepick");
  const zone = document.getElementById("dropzone");

  const fmtSize = (n) => {
    n = Number(n);
    if (n < 1024) return n + " B";
    const u = ["KB", "MB", "GB", "TB"];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n < 10 ? 1 : 0) + " " + u[i];
  };
  const fmtTime = (ts) => {
    const d = new Date(Number(ts) * 1000);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " +
      d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  };
  const decorate = () => {
    document.querySelectorAll("td[data-size]").forEach((td) => (td.textContent = fmtSize(td.dataset.size)));
    document.querySelectorAll("td[data-ts]").forEach((td) => td.dataset.ts && (td.textContent = fmtTime(td.dataset.ts)));
  };
  decorate();

  const say = (msg) => (progress.textContent = msg);
  const api = async (method, path, body) => {
    const res = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: Object.assign({ "X-CSRF-Token": csrf }, body ? { "Content-Type": "application/json" } : {}),
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = {};
    try { data = await res.json(); } catch (_) {}
    if (!res.ok) throw new Error(data.error || "HTTP " + res.status);
    return { status: res.status, data };
  };

  // XHR for upload progress; resolves with the response ETag.
  const put = (url, blob, onProgress, headers) => new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    x.open("PUT", url);
    Object.entries(headers || {}).forEach(([k, v]) => x.setRequestHeader(k, v));
    x.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded);
    x.onload = () => (x.status >= 200 && x.status < 300)
      ? resolve(x.getResponseHeader("ETag") || "")
      : reject(new Error("upload failed: HTTP " + x.status));
    x.onerror = () => reject(new Error("network error during upload"));
    x.send(blob);
  });

  async function uploadRemote(file, report) {
    const { data: sess } = await api("POST", "/account/api/uploads", { name: file.name, size: file.size, mime: file.type });
    if (sess.file) return; // already in the drive (same content): instant
    const id = sess.upload_id;
    if (sess.mode === "single") {
      await put(sess.put_url, file, (n) => report(n));
      const done = await api("POST", "/account/api/uploads/" + id + "/complete");
      if (done.status === 202) await waitVerified(id);
      return;
    }
    const partSize = sess.part_size, total = sess.parts;
    const urls = {};
    (sess.part_urls || []).forEach((p) => (urls[p.part_number] = p.url));
    const loaded = new Array(total + 1).fill(0);
    const parts = [];
    let next = 1;
    const sum = () => loaded.reduce((a, b) => a + b, 0);
    const worker = async () => {
      while (next <= total) {
        const n = next++;
        if (!urls[n]) {
          const want = [];
          for (let k = n; k <= Math.min(total, n + 99); k++) if (!urls[k]) want.push(k);
          const { data } = await api("POST", "/account/api/uploads/" + id + "/parts", { part_numbers: want });
          data.part_urls.forEach((p) => (urls[p.part_number] = p.url));
        }
        const blob = file.slice((n - 1) * partSize, Math.min(file.size, n * partSize));
        let etag = "", tries = 0;
        for (;;) {
          try { etag = await put(urls[n], blob, (b) => { loaded[n] = b; report(sum()); }); break; }
          catch (e) { if (++tries >= 3) throw e; await new Promise((r) => setTimeout(r, 1000 * tries)); }
        }
        loaded[n] = blob.size;
        parts.push({ part_number: n, etag });
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
    // An empty ETag (storage CORS hides it) lets the server list parts itself.
    const body = parts.every((p) => p.etag) ? { parts } : undefined;
    const done = await api("POST", "/account/api/uploads/" + id + "/complete", body);
    if (done.status === 202) await waitVerified(id);
  }

  async function waitVerified(id) {
    for (let i = 0; i < 600; i++) {
      say("Verifying sha256…");
      await new Promise((r) => setTimeout(r, 2000));
      const { data } = await api("GET", "/account/api/uploads/" + id);
      if (data.status === "done") return;
      if (data.status === "failed" || data.status === "expired") throw new Error(data.error || "upload failed");
    }
    throw new Error("verification is taking long — check back in a minute");
  }

  async function uploadDirect(file, report) {
    await put("/account/api/files/" + encodeURIComponent(file.name), file, report,
      { "X-CSRF-Token": csrf, "Content-Type": file.type || "application/octet-stream" });
  }

  async function uploadAll(files) {
    for (const file of files) {
      const t0 = Date.now();
      const report = (n) => {
        const pct = file.size ? Math.min(100, Math.floor((n / file.size) * 100)) : 100;
        const secs = (Date.now() - t0) / 1000;
        const rate = secs > 0.5 ? " · " + fmtSize(n / secs) + "/s" : "";
        say(file.name + " — " + pct + "%" + rate);
      };
      try {
        say(file.name + " — starting…");
        await (remote ? uploadRemote : uploadDirect)(file, report);
        say(file.name + " — saved ✓");
      } catch (e) {
        say(file.name + " — " + e.message);
        return refresh();
      }
    }
    refresh();
  }

  async function refresh() {
    try {
      const { data } = await api("GET", "/account/api/files");
      tbody.textContent = "";
      if (!data.files.length) {
        tbody.innerHTML = '<tr class="empty"><td colspan="4" class="dim small" style="padding:18px 6px">Nothing here yet.</td></tr>';
      }
      data.files.forEach((f) => {
        const tr = document.createElement("tr");
        tr.dataset.sha = f.sha256;
        tr.dataset.name = f.name;
        const ts = Math.floor(new Date(f.created_at).getTime() / 1000);
        tr.innerHTML =
          '<td class="trunc"></td><td class="num" data-size="' + f.size + '"></td>' +
          '<td class="hide-sm dim small" data-ts="' + ts + '"></td>' +
          '<td style="text-align:right;white-space:nowrap"><a class="btn sm ghost">Download</a> ' +
          '<button class="btn sm ghost" type="button" data-act="link">Link</button> ' +
          '<button class="btn sm ghost danger" type="button" data-act="delete">Delete</button></td>';
        tr.firstChild.textContent = f.name;
        tr.firstChild.title = f.name + " · sha256 " + f.sha256;
        tr.querySelector("a").href = "/account/api/files/" + f.sha256 + "/content";
        tbody.appendChild(tr);
      });
      decorate();
      const used = data.storage_used, quota = data.storage_quota;
      document.getElementById("usage").textContent = fmtSize(used) + " of " + fmtSize(quota);
      document.getElementById("meterbar").style.width = (quota ? Math.min(100, (used * 100) / quota) : 0) + "%";
    } catch (e) { say(e.message); }
  }

  pick.addEventListener("change", () => pick.files.length && uploadAll([...pick.files]).then(() => (pick.value = "")));
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove("over"); }));
  zone.addEventListener("drop", (e) => e.dataTransfer.files.length && uploadAll([...e.dataTransfer.files]));

  tbody.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const tr = btn.closest("tr");
    const sha = tr.dataset.sha, name = tr.dataset.name;
    if (btn.dataset.act === "delete") {
      if (!confirm("Delete " + name + "? Its links stop working.")) return;
      try {
        await api("DELETE", "/account/api/files/" + sha + "?entry=" + encodeURIComponent(name));
        tr.remove();
        say(name + " deleted");
        refresh();
      } catch (err) { say(err.message); }
    } else if (btn.dataset.act === "link") {
      try {
        const { data } = await api("POST", "/account/api/links", { file: "sha256:" + sha, ttl: "24h" });
        await navigator.clipboard.writeText(data.url).catch(() => {});
        say("Link copied (works for 24h): " + data.url);
      } catch (err) { say(err.message); }
    }
  });

  document.querySelectorAll("[data-copy]").forEach((b) =>
    b.addEventListener("click", () => {
      const el = document.querySelector(b.dataset.copy);
      navigator.clipboard.writeText(el.textContent.trim()).then(() => {
        const old = b.textContent;
        b.textContent = "Copied";
        setTimeout(() => (b.textContent = old), 1500);
      });
    })
  );
})();
