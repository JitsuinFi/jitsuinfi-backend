// HNK-34 E2E (finding 3): a first-time buyer's "Show my next invoice key" reads the history copy
// at GET /api/mailbox/:id/state. With nothing saved that is a plain 404 the browser takes as "no
// copy yet"; production answered 500 because its relay_state table was never created. The relay
// now applies db/*.sql on start and names a missing table as such (503), never a bare 500.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { applyMigrations, migrationFiles, MIGRATIONS } from "../src/schema.ts";
import { MemoryStore } from "../src/store.ts";
import { client, harness } from "./flow.ts";

test("a new mailbox has no saved state yet: 404, not an error", async () => {
  const h = harness(new MemoryStore());
  const a = client();
  assert.equal((await h.register(a)).status, 201);
  const r = await h.call("GET", `/api/mailbox/${a.id}/state`, undefined, { Authorization: `Bearer ${await h.token(a)}` });
  assert.equal(r.status, 404);
  assert.deepEqual(await r.json(), { error: "this mailbox has no saved state" });
});

test("a missing table answers 503 with a sentence, not 500", async () => {
  class NoStateTable extends MemoryStore {
    override async getState(): Promise<undefined> {
      throw Object.assign(new Error('relation "relay_state" does not exist'), { code: "42P01" });
    }
  }
  const h = harness(new NoStateTable());
  const a = client();
  await h.register(a);
  const r = await h.call("GET", `/api/mailbox/${a.id}/state`, undefined, { Authorization: `Bearer ${await h.token(a)}` });
  assert.equal(r.status, 503);
  assert.match(((await r.json()) as { error: string }).error, /database is not set up/);
});

test("the migrations include relay_state and apply in name order", async () => {
  const files = migrationFiles();
  assert.deepEqual(files, [...files].sort());
  assert.deepEqual(files.slice(0, 2), ["001_relay.sql", "002_state.sql"]);
  assert.match(readFileSync(new URL("002_state.sql", MIGRATIONS), "utf8"), /create table if not exists relay_state/);
  const ran: string[] = [];
  assert.deepEqual(await applyMigrations(async (text) => void ran.push(text)), files);
  assert.equal(ran.length, files.length);
  assert.match(ran[1], /relay_state/);
});
