(() => {
  const PLUGIN_ID = "botkiller";
  const params = new URLSearchParams(window.location.search);

  const clientInput = document.getElementById("client-id");
  const scanBtn = document.getElementById("scan-btn");
  const remediateBtn = document.getElementById("remediate-btn");
  const dryRunBox = document.getElementById("dry-run");
  const checkAll = document.getElementById("check-all");
  const tbody = document.getElementById("findings-body");
  const countEl = document.getElementById("findings-count");
  const statusPill = document.getElementById("status-pill");
  const logEl = document.getElementById("status-log");

  clientInput.value = params.get("clientId") || "";

  let findings = [];
  const selected = new Set();
  let pollTimer = null;

  function log(line) {
    const ts = new Date().toLocaleTimeString();
    logEl.textContent = `${ts} ${line}\n` + logEl.textContent;
  }

  function setStatus(text, cls) {
    statusPill.textContent = text;
    statusPill.classList.toggle("loading", cls === "loading");
    statusPill.classList.toggle("error", cls === "error");
  }

  function escapeHtml(text) {
    return String(text ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[ch]));
  }

  function getClientId() {
    return clientInput.value.trim();
  }

  async function sendEvent(event, payload = {}) {
    const clientId = getClientId();
    if (!clientId) {
      log("Missing clientId");
      throw new Error("Missing clientId");
    }
    const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}/plugins/${PLUGIN_ID}/event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, payload }),
    });
    if (!res.ok) {
      const text = await res.text();
      log(`Send failed: ${res.status} ${text}`);
      throw new Error(text);
    }
    log(`Sent ${event}`);
  }

  async function pollEvents() {
    const clientId = getClientId();
    if (!clientId) return;
    try {
      const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}/plugins/${PLUGIN_ID}/events`);
      if (!res.ok) return;
      const data = await res.json();
      for (const item of data.events || []) handlePluginEvent(item.event, item.payload);
    } catch (_) {}
  }

  function handlePluginEvent(event, payload) {
    if (event === "ready") {
      log(payload?.message || "botkiller ready");
      return;
    }
    if (event === "scan_result") {
      findings = Array.isArray(payload?.findings) ? payload.findings : [];
      selected.clear();
      renderFindings();
      setStatus("Ready");
      log(`Scan complete: ${findings.length} findings (${payload?.whitelisted_count ?? 0} whitelisted)`);
      return;
    }
    if (event === "remediate_result") {
      setStatus("Ready");
      const results = Array.isArray(payload?.results) ? payload.results : [];
      const s = payload?.summary || {};
      log(`Remediate ${payload?.dry_run ? "(dry run) " : ""}done: ${s.succeeded ?? 0}/${s.targets ?? results.length} ok`);
      for (const r of results) {
        for (const a of r.actions || []) log(`  [${r.id}] ${a}`);
        for (const e of r.errors || []) log(`  [${r.id}] ERROR: ${e}`);
      }
      // Refresh findings after remediation.
      sendEvent("scan", {}).catch(() => {});
      setStatus("Rescanning", "loading");
      return;
    }
    if (event === "whitelist_result") {
      log(`Whitelist updated: +${payload?.added_paths ?? 0} paths, +${payload?.added_names ?? 0} names`);
      return;
    }
    if (event === "pong") {
      log("pong");
    }
  }

  function verdictBadge(verdict) {
    const cls = verdict === "suspicious" ? "suspicious" : verdict === "trusted" ? "trusted" : "clean";
    return `<span class="badge ${cls}">${escapeHtml(verdict)}</span>`;
  }

  function renderFindings() {
    const sorted = [...findings].sort((a, b) => (b.score || 0) - (a.score || 0));
    countEl.textContent = `${findings.length} total, ${findings.filter((f) => f.verdict === "suspicious").length} suspicious`;
    checkAll.checked = sorted.length > 0 && sorted.every((f) => f.verdict !== "suspicious" || selected.has(f.id));

    if (sorted.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty">No findings.</td></tr>';
      remediateBtn.disabled = true;
      return;
    }

    tbody.innerHTML = sorted.map((f) => {
      const suspicious = f.verdict === "suspicious";
      const checked = selected.has(f.id) ? "checked" : "";
      const checkbox = suspicious
        ? `<input type="checkbox" class="row-check" data-id="${escapeHtml(f.id)}" ${checked} />`
        : "";
      const persistence = (f.persistence || []).map((p) => `${p.kind}:${p.name}`).join(", ");
      const pid = f.pid != null ? ` [pid ${f.pid}]` : "";
      return `<tr class="${suspicious ? "row-suspicious" : ""}">
        <td class="col-check">${checkbox}</td>
        <td>${verdictBadge(f.verdict)}</td>
        <td>${f.score ?? 0}</td>
        <td>${escapeHtml(f.kind)}${pid}</td>
        <td title="${escapeHtml(f.name)}">${escapeHtml(f.name)}</td>
        <td title="${escapeHtml(f.path || "")}">${escapeHtml(f.path || "")}</td>
        <td class="reasons">${escapeHtml((f.reasons || []).join("; "))}</td>
        <td title="${escapeHtml(persistence)}">${escapeHtml(persistence)}</td>
      </tr>`;
    }).join("");
    updateRemediateButton();
  }

  function updateRemediateButton() {
    remediateBtn.disabled = selected.size === 0;
    remediateBtn.textContent = selected.size > 0 ? `Remediate selected (${selected.size})` : "Remediate selected";
  }

  scanBtn.addEventListener("click", () => {
    setStatus("Scanning", "loading");
    sendEvent("scan", {}).catch(() => setStatus("Error", "error"));
  });

  remediateBtn.addEventListener("click", () => {
    const targets = findings.filter((f) => selected.has(f.id)).map((f) => f.id);
    if (targets.length === 0) return;
    const dryRun = dryRunBox.checked;
    const label = dryRun ? "Dry-run remediate" : "REMEDIATE (kill processes, delete files, remove persistence)";
    if (!confirm(`${label} ${targets.length} target(s) on ${getClientId()}?`)) return;
    setStatus("Remediating", "loading");
    sendEvent("remediate", { targets, dry_run: dryRun }).catch(() => setStatus("Error", "error"));
  });

  checkAll.addEventListener("change", () => {
    for (const f of findings) {
      if (f.verdict !== "suspicious") continue;
      if (checkAll.checked) selected.add(f.id);
      else selected.delete(f.id);
    }
    renderFindings();
  });

  tbody.addEventListener("change", (e) => {
    const box = e.target.closest(".row-check");
    if (!box) return;
    if (box.checked) selected.add(box.dataset.id);
    else selected.delete(box.dataset.id);
    updateRemediateButton();
  });

  clientInput.addEventListener("change", () => {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(pollEvents, 900);
  });

  pollTimer = setInterval(pollEvents, 900);
})();
