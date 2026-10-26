// Shared relay scenario, run against any Store (memory always, Postgres when TEST_DATABASE_URL is
// set). The client side is emulated with Node crypto, as jitsuin-wasm will do it (HNK-23.T2).
import assert from "node:assert/strict";
import { createApp } from "../src/app.ts";
import type { Config } from "../src/config.ts";
import { ephemeral, mailboxId, proofTag, x25519, type Purpose } from "../src/crypto.ts";
import type { Store } from "../src/store.ts";

export const cfg: Config = { port: 0, databaseUrl: undefined, retentionDays: 30, maxMessagesPerMailbox: 3, challengeTtlSeconds: 120, readTokenTtlSeconds: 600 };

export class Clock {
  t = new Date("2026-10-20T10:00:00Z");
  now = () => this.t;
  advance(seconds: number) {
    this.t = new Date(this.t.getTime() + seconds * 1000);
  }
}

export function client() {
  const k = ephemeral();
  return { secret: k.secret, pk: k.public, pkHex: k.public.toString("hex"), id: mailboxId(k.public) };
}
export type Client = ReturnType<typeof client>;

export function harness(store: Store, clock = new Clock()) {
  const app = createApp(store, cfg, clock.now);
  const call = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
    app.request(path, {
      method,
      headers: body instanceof Uint8Array ? { "Content-Type": "application/octet-stream", ...headers } : body ? { "Content-Type": "application/json", ...headers } : headers,
      body: body instanceof Uint8Array ? new Blob([new Uint8Array(body)]) : body ? JSON.stringify(body) : undefined,
    });
  const challenge = async (c: Client, purpose: Purpose) => (await (await call("POST", "/api/mailbox/challenge", { mailbox_pk: c.pkHex, purpose })).json()) as { challenge_id: string; eph_pk: string; nonce: string };
  const answer = (c: Client, purpose: Purpose, ch: { eph_pk: string; nonce: string }) =>
    proofTag(purpose, x25519(c.secret, c.pk, Buffer.from(ch.eph_pk, "hex")), Buffer.from(ch.nonce, "hex"), c.pk).toString("hex");
  const register = async (c: Client) => {
    const ch = await challenge(c, "register");
    return call("POST", "/api/mailbox", { mailbox_pk: c.pkHex, challenge_id: ch.challenge_id, proof: answer(c, "register", ch) });
  };
  const token = async (c: Client) => {
    const ch = await challenge(c, "read");
    const r = await call("POST", `/api/mailbox/${c.id}/read`, { challenge_id: ch.challenge_id, proof: answer(c, "read", ch) });
    return ((await r.json()) as { token: string }).token;
  };
  return { app, call, challenge, answer, register, token, clock };
}

export async function fullScenario(store: Store) {
  const h = harness(store);
  const alice = client();
  const bob = client();

  // register: the relay's id is the client's; a second registration is harmless
  let r = await h.register(alice);
  assert.equal(r.status, 201);
  assert.deepEqual(await r.json(), { mailbox_id: alice.id, created: true });
  r = await h.register(alice);
  assert.deepEqual([r.status, ((await r.json()) as { created: boolean }).created], [200, false]);
  assert.equal((await h.register(bob)).status, 201);

  // anyone may drop a sealed message in a known mailbox
  const sealed = new Uint8Array(200).map((_, i) => i);
  r = await h.call("POST", `/api/mailbox/${alice.id}/messages`, sealed);
  assert.equal(r.status, 202);
  const { message_id } = (await r.json()) as { message_id: string };

  // only the owner lists and fetches it
  assert.equal((await h.call("GET", `/api/mailbox/${alice.id}/messages`)).status, 401);
  const bobToken = await h.token(bob);
  assert.equal((await h.call("GET", `/api/mailbox/${alice.id}/messages`, undefined, { Authorization: `Bearer ${bobToken}` })).status, 401);
  const t = await h.token(alice);
  const auth = { Authorization: `Bearer ${t}` };
  r = await h.call("GET", `/api/mailbox/${alice.id}/messages`, undefined, auth);
  const list = ((await r.json()) as { messages: Array<{ id: string; size: number }> }).messages;
  assert.deepEqual(list.map((m) => [m.id, m.size]), [[message_id, 200]]);
  r = await h.call("GET", `/api/mailbox/${alice.id}/messages/${message_id}`, undefined, auth);
  assert.equal(r.headers.get("Content-Type"), "application/octet-stream");
  assert.deepEqual(new Uint8Array(await r.arrayBuffer()), sealed);
  assert.equal((await h.call("DELETE", `/api/mailbox/${alice.id}/messages/${message_id}`, undefined, auth)).status, 204);
  assert.equal((await h.call("GET", `/api/mailbox/${alice.id}/messages/${message_id}`, undefined, auth)).status, 404);

  // HNK-25.T2: the owner's sealed state, replaced on write, only for the owner, kept past retention
  const st = `/api/mailbox/${alice.id}/state`;
  assert.equal((await h.call("GET", st, undefined, auth)).status, 204); // nothing saved yet
  assert.equal((await h.call("PUT", st, sealed)).status, 401);
  assert.equal((await h.call("PUT", st, sealed, { Authorization: `Bearer ${bobToken}` })).status, 401);
  assert.equal((await h.call("PUT", st, new Uint8Array(48), auth)).status, 400);
  assert.equal((await h.call("PUT", st, new Uint8Array(64 * 1024 + 49), auth)).status, 413);
  assert.equal((await h.call("PUT", st, sealed, auth)).status, 200);
  const newer = new Uint8Array(300).fill(7);
  assert.equal((await h.call("PUT", st, newer, auth)).status, 200);
  assert.equal((await h.call("GET", st, undefined, { Authorization: `Bearer ${bobToken}` })).status, 401);
  assert.deepEqual(new Uint8Array(await (await h.call("GET", st, undefined, auth)).arrayBuffer()), newer);

  // retention: a message left unread expires
  await h.call("POST", `/api/mailbox/${bob.id}/messages`, sealed);
  h.clock.advance(31 * 86_400);
  const fresh = await h.token(bob);
  r = await h.call("GET", `/api/mailbox/${bob.id}/messages`, undefined, { Authorization: `Bearer ${fresh}` });
  assert.deepEqual(((await r.json()) as { messages: unknown[] }).messages, []);
  assert.ok((await store.purge(h.clock.now())) >= 1);
  const later = await h.token(alice);
  assert.deepEqual(new Uint8Array(await (await h.call("GET", st, undefined, { Authorization: `Bearer ${later}` })).arrayBuffer()), newer);
  return { alice, bob };
}
