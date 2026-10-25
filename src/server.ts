// Relay process: Postgres when DATABASE_URL is set (Railway, D-33), memory otherwise (local).
import { serve } from "@hono/node-server";
import { createApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { PostgresStore } from "./pg-store.ts";
import { MemoryStore, type Store } from "./store.ts";

const cfg = loadConfig();
const store: Store = cfg.databaseUrl ? new PostgresStore(cfg.databaseUrl) : new MemoryStore();
const app = createApp(store, cfg);
try {
  await store.ready?.();
} catch (e) {
  // without its tables the relay would answer 500 to the endpoints that need them: do not start
  console.error("relay: the database is not ready:", e instanceof Error ? e.message : e);
  process.exit(1);
}

const purge = setInterval(() => {
  store.purge(new Date()).then(
    (n) => n && console.log(`relay: ${n} expired message(s) removed`),
    (e) => console.error("relay purge failed:", e instanceof Error ? e.message : e),
  );
}, 10 * 60 * 1000);

const server = serve({ fetch: app.fetch, port: cfg.port }, (info) => {
  console.log(`relay listening on :${info.port} (${cfg.databaseUrl ? "postgres" : "memory store: messages are lost on restart"})`);
});

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    clearInterval(purge);
    server.close();
    store.close().finally(() => process.exit(0));
  });
}
