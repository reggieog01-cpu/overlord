/*
 * vmon server plugin — session forwarding between the client-side DLL and
 * the Virtual Monitor panel page.
 *
 * The server is a dumb forwarder by design (RAM discipline): frame events
 * from the agent are broadcast to SSE listeners immediately and never
 * retained. Viewer input goes the other way via the client event endpoint.
 */

export default {
  setup(ctx) {
    ctx.log.info("vmon plugin ready");
  },

  teardown() {},

  onEvent(ctx, clientId, event, payload) {
    if (typeof event !== "string" || !event.startsWith("vmon_")) return;
    // Attach the source client so viewers can filter; forward immediately.
    ctx.broadcast(event, { clientId, ...(payload && typeof payload === "object" ? payload : { data: payload }) });
  },

  rpc: {
    /// Lightweight liveness/status for the panel page.
    status(ctx) {
      return { ok: true };
    },
  },
};
