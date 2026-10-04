/*
 * vmon side-channel transport.
 *
 * The plugin event channel (base64 JSON over SSE) is fine for control but
 * terrible for video: per-frame JSON parse, worker round-trips and SSE text.
 * This module gives the agent-side vmon DLL a direct binary WebSocket to the
 * server, and viewers a matching binary feed — the same raw-bytes relay the
 * built-in backstage transport enjoys.
 *
 * Flow:
 *   panel POSTs /api/plugins/vmon/agent-token {clientId}     → one-time token
 *   panel sends plugin event "start" {token, wsUrl, ...}      → DLL connects
 *   DLL  → WS /api/plugins/vmon/agent-ws?token=<token>        → binary frames
 *   panel → WS /api/plugins/vmon/viewer-ws?clientId=<id>      → FRM frames
 */

import type { ServerWebSocket } from "bun";
import type { SocketData } from "../sessions/types";import { buildViewerFrameBuffer } from "./ws-viewer-utils";

const AGENT_TOKEN_TTL_MS = 2 * 60 * 1000;
const MAX_VIEWER_BUFFERED_BYTES = 8 * 1024 * 1024;

type AgentToken = { clientId: string; expiresAt: number };
const agentTokens = new Map<string, AgentToken>();

const agents = new Map<string, ServerWebSocket<SocketData>>();
const viewers = new Map<string, Set<ServerWebSocket<SocketData>>>();

setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of agentTokens) {
    if (entry.expiresAt < now) agentTokens.delete(token);
  }
}, 60_000);

export function issueAgentToken(clientId: string): string {
  const token = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  agentTokens.set(token, { clientId, expiresAt: Date.now() + AGENT_TOKEN_TTL_MS });
  return token;
}

export function consumeAgentToken(token: string): string | null {
  const entry = agentTokens.get(token);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    agentTokens.delete(token);
    return null;
  }
  // single-use
  agentTokens.delete(token);
  return entry.clientId;
}

function viewersFor(clientId: string): Set<ServerWebSocket<SocketData>> {
  let set = viewers.get(clientId);
  if (!set) {
    set = new Set();
    viewers.set(clientId, set);
  }
  return set;
}

export function vmonAgentOpen(ws: ServerWebSocket<SocketData>) {
  agents.set(ws.data.clientId, ws);
  // greet the DLL so it knows the channel is live
  try {
    ws.send(JSON.stringify({ type: "ready" }));
  } catch {}
}

export function vmonAgentMessage(
  ws: ServerWebSocket<SocketData>,
  raw: string | ArrayBuffer | Uint8Array,
) {
  const clientId = ws.data.clientId;
  const set = viewers.get(clientId);
  if (!set || set.size === 0) return;
  if (typeof raw === "string") return; // control messages are ignored for now

  const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
  // H.264 annexb access unit straight through; FRM format=4.
  const buf = buildViewerFrameBuffer(bytes, { format: "h264", monitor: 0, fps: 0 });
  for (const viewer of set) {
    if ((viewer.getBufferedAmount?.() ?? 0) > MAX_VIEWER_BUFFERED_BYTES) {
      // drop for the slow viewer, never queue
      continue;
    }
    try {
      viewer.send(buf);
    } catch {}
  }
}

export function vmonViewerOpen(ws: ServerWebSocket<SocketData>) {
  viewersFor(ws.data.clientId).add(ws);
  try {
    ws.send(JSON.stringify({ type: "hello", clientId: ws.data.clientId }));
  } catch {}
}

export function vmonViewerMessage() {
  // viewers currently have nothing meaningful to say on the side channel;
  // input/control stays on the plugin event channel by design.
}

export function vmonClose(ws: ServerWebSocket<SocketData>) {
  if (agents.get(ws.data.clientId) === ws) agents.delete(ws.data.clientId);
  const set = viewers.get(ws.data.clientId);
  if (set) {
    set.delete(ws);
    if (set.size === 0) viewers.delete(ws.data.clientId);
  }
}
