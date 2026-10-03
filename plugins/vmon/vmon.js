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

  /* ── H.264 decode (WebCodecs) ── */

  let decoder = null;
  let decodedW = 0, decodedH = 0;

  // Parse SPS NAL from an annexb sequence header to build the codec string.
  function codecFromSeqhdr(bytes) {
    for (let i = 0; i + 4 < bytes.length; i++) {
      const sc3 = bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 1;
      const sc4 = bytes[i] === 0 && bytes[i + 1] === 0 && bytes[i + 2] === 0 && bytes[i + 3] === 1;
      if (!sc3 && !sc4) continue;
      const nalStart = i + (sc4 ? 4 : 3);
      const nalType = bytes[nalStart] & 0x1f;
      if (nalType === 7 && nalStart + 3 < bytes.length) {
        const p = bytes[nalStart + 1], c = bytes[nalStart + 2], l = bytes[nalStart + 3];
        const hex = (b) => b.toString(16).padStart(2, "0").toUpperCase();
        return `avc1.${hex(p)}${hex(c)}${hex(l)}`;
      }
    }
    return "avc1.640028"; // High 4.0 fallback
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
        // First decoded frame: hide the overlay regardless of how we got here
        // (stream may have started before the page loaded).
        if (!overlay.classList.contains("hidden")) overlay.classList.add("hidden");
      },
      error: (e) => log(`decoder: ${e.message}`),
    });
    const tryConfigure = (config) => {
      try {
        decoder.configure(config);
        return true;
      } catch {
        return false;
      }
    };
    // Let the browser pick the decode backend — hardwareAcceleration hints
    // fail configure() outright on machines without a GPU.
    if (!tryConfigure({ codec, format: "annexb" })
        && !tryConfigure({ codec })
        && !tryConfigure({ codec: "avc1.640028", format: "annexb" })) {
      log(`decoder: cannot configure for ${codec}`);
      return;
    }
    // Feed SPS/PPS as a config chunk.
    decoder.decode(new EncodedVideoChunk({ type: "key", timestamp: 0, data: bytes }));
    log(`decoder: configured ${w}x${h} (${codec})`);
  }

  /* ── stream (SSE) ── */

  let framesRendered = 0;
  let bytesIn = 0;
  let streaming = false;

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
        setStatus("live", "live");
        overlay.classList.add("hidden");
        $("vm-start").disabled = true;
        $("vm-stop").disabled = false;
      } else if (stage === "error") {
        setStatus("error", "error");
        $("vm-start").disabled = false;
        $("vm-stop").disabled = true;
      } else if (stage === "stopped") {
        streaming = false;
        setStatus("stopped", "");
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

  source.addEventListener("vmon_frame", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (!mine(d) || !decoder || decoder.state !== "configured") return;
      const bytes = Uint8Array.from(atob(d.data), (c) => c.charCodeAt(0));
      bytesIn += bytes.length;
      // Drop delta frames when the decoder is behind; never drop keyframes.
      if (decoder.decodeQueueSize > 4 && !d.key) return;
      decoder.decode(
        new EncodedVideoChunk({
          type: d.key ? "key" : "delta",
          timestamp: (d.ts || 0) * 1000,
          data: bytes,
        }),
      );
    } catch {}
  });

  source.addEventListener("vmon_apps", (e) => {
    try {
      const d = JSON.parse(e.data);
      if (!mine(d)) return;
      const sel = $("vm-apps");
      sel.innerHTML = '<option value="">Select app…</option>';
      for (const app of d.apps || []) {
        const opt = document.createElement("option");
        opt.value = app.path;
        opt.textContent = app.name;
        sel.appendChild(opt);
      }
      log(`apps: ${(d.apps || []).length} found`);
    } catch {}
  });

  source.onerror = () => setStatus("stream error", "error");

  /* ── stats ── */
  setInterval(() => {
    $("vm-pill-fps").textContent = `${framesRendered} fps`;
    $("vm-pill-bw").textContent = `${Math.round((bytesIn * 8) / 1000)} kbps`;
    framesRendered = 0;
    bytesIn = 0;
  }, 1000);

  /* ── controls ── */

  $("vm-start").addEventListener("click", async () => {
    const [w, h] = $("vm-res").value.split("x").map(Number);
    setStatus("starting…", "");
    overlay.textContent = "Starting virtual display…";
    try {
      await sendEvent("start", {
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
  });

  $("vm-keyframe").addEventListener("click", () => sendEvent("keyframe").catch(() => {}));

  $("vm-refresh-apps").addEventListener("click", () => {
    $("vm-apps").innerHTML = "<option value=''>Loading…</option>";
    sendEvent("list_apps").catch((e) => log(String(e)));
  });

  $("vm-launch").addEventListener("click", () => {
    const path = $("vm-apps").value;
    if (!path) return;
    sendEvent("launch", { path }).catch((e) => log(String(e)));
  });

  $("vm-launch-custom").addEventListener("click", () => {
    const path = $("vm-custom-path").value.trim();
    if (!path) return;
    sendEvent("launch", { path }).catch((e) => log(String(e)));
  });

  $("vm-explorer").addEventListener("click", () => {
    sendEvent("launch", { path: "C:\\Windows\\explorer.exe" }).catch((e) => log(String(e)));
  });

  $("vm-fullscreen").addEventListener("click", () => {
    const stage = $("vm-stage");
    if (document.fullscreenElement) document.exitFullscreen();
    else stage.requestFullscreen().catch(() => {});
  });

  /* ── input ── */

  let inputEnabled = false;
  $("vm-input-toggle").addEventListener("click", () => {
    inputEnabled = !inputEnabled;
    const btn = $("vm-input-toggle");
    btn.classList.toggle("on", inputEnabled);
    btn.querySelector("span").textContent = inputEnabled ? "Input on" : "Input off";
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

  // Boot: fetch app list once the plugin is reachable, then ask for a
  // keyframe + config replay so a stream already in progress shows up.
  if (clientId) {
    sendEvent("ping")
      .then(() => sendEvent("list_apps"))
      .then(() => sendEvent("keyframe"))
      .catch((err) => {
        setStatus("unreachable", "error");
        log(String(err));
      });
  }
})();
