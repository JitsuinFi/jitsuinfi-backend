// HNK-23.T3, T4: relay API against the memory store, run with `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MAX_CIPHERTEXT } from "../src/config.ts";
import { mailboxId, proofTag, x25519 } from "../src/crypto.ts";
import { MemoryStore } from "../src/store.ts";
import { client, fullScenario, harness } from "./flow.ts";

test("register, send, list, fetch, remove, expire (AC-HNK-23.2 – 23.4)", async () => {
  await fullScenario(new MemoryStore());
});

test("registration needs a fresh, matching proof", async () => {
  const h = harness(new MemoryStore());
  const a = client();
  const other = client();
  const ch = await h.challenge(a, "register");
  const bad = await h.call("POST", "/api/mailbox", { mailbox_pk: a.pkHex, challenge_id: ch.challenge_id, proof: "00".repeat(32) });
  assert.equal(bad.status, 403);
  // the failed attempt used the challenge up
  const reuse = await h.call("POST", "/api/mailbox", { mailbox_pk: a.pkHex, challenge_id: ch.challenge_id, proof: h.answer(a, "register", ch) });
  assert.equal(reuse.status, 403);
  // a proof computed by someone who only knows mailbox_pk (here: with another secret) fails
  const ch2 = await h.challenge(a, "register");
  const forged = proofTag("register", x25519(other.secret, other.pk, Buffer.from(ch2.eph_pk, "hex")), Buffer.from(ch2.nonce, "hex"), a.pk).toString("hex");
  assert.equal((await h.call("POST", "/api/mailbox", { mailbox_pk: a.pkHex, challenge_id: ch2.challenge_id, proof: forged })).status, 403);
  // a challenge made for another key, or for reading, does not register
  const ch3 = await h.challenge(other, "register");
  assert.equal((await h.call("POST", "/api/mailbox", { mailbox_pk: a.pkHex, challenge_id: ch3.challenge_id, proof: h.answer(other, "register", ch3) })).status, 403);
  const ch4 = await h.challenge(a, "read");
  assert.equal((await h.call("POST", "/api/mailbox", { mailbox_pk: a.pkHex, challenge_id: ch4.challenge_id, proof: h.answer(a, "read", ch4) })).status, 403);
  // an expired challenge
  const ch5 = await h.challenge(a, "register");
  h.clock.advance(121);
  assert.equal((await h.call("POST", "/api/mailbox", { mailbox_pk: a.pkHex, challenge_id: ch5.challenge_id, proof: h.answer(a, "register", ch5) })).status, 403);
  // nothing was registered by any of these
  assert.equal((await h.call("POST", `/api/mailbox/${a.id}/messages`, new Uint8Array(100))).status, 404);
  assert.equal((await h.register(a)).status, 201);
});

test("low-order and malformed keys are refused", async () => {
  const h = harness(new MemoryStore());
  for (const pk of ["00".repeat(32), "01" + "00".repeat(31), "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"]) {
    const r = await h.call("POST", "/api/mailbox/challenge", { mailbox_pk: pk, purpose: "register" });
    assert.equal(r.status, 400, pk);
    assert.match(((await r.json()) as { error: string }).error, /not a usable X25519 key/);
  }
  const r = await h.call("POST", "/api/mailbox/challenge", { mailbox_pk: "XYZ", purpose: "register" });
  assert.match(((await r.json()) as { error: string }).error, /64 lowercase hex/);
  assert.equal((await h.call("POST", "/api/mailbox/challenge", { mailbox_pk: client().pkHex, purpose: "write" })).status, 400);
});

test("sending: size, type, unknown mailbox, full mailbox", async () => {
  const h = harness(new MemoryStore());
  const a = client();
  await h.register(a);
  const to = `/api/mailbox/${a.id}/messages`;
  assert.equal((await h.call("POST", `/api/mailbox/${"ab".repeat(32)}/messages`, new Uint8Array(100))).status, 404);
  assert.equal((await h.call("POST", to, new Uint8Array(48))).status, 400);
  assert.equal((await h.call("POST", to, { not: "sealed" })).status, 400);
  const big = await h.call("POST", to, new Uint8Array(MAX_CIPHERTEXT + 1));
  assert.equal(big.status, 413);
  assert.match(((await big.json()) as { error: string }).error, /two 2 MiB PDFs/);
  assert.equal((await h.call("POST", to, new Uint8Array(MAX_CIPHERTEXT))).status, 202);
  for (let i = 0; i < 2; i++) assert.equal((await h.call("POST", to, new Uint8Array(100))).status, 202);
  assert.equal((await h.call("POST", to, new Uint8Array(100))).status, 429);
});

test("read tokens are per mailbox and expire", async () => {
  const h = harness(new MemoryStore());
  const a = client();
  const b = client();
  await h.register(a);
  await h.register(b);
  // a read proof for b presented at a's read endpoint
  const ch = await h.challenge(b, "read");
  assert.equal((await h.call("POST", `/api/mailbox/${a.id}/read`, { challenge_id: ch.challenge_id, proof: h.answer(b, "read", ch) })).status, 403);
  const t = await h.token(a);
  assert.equal((await h.call("GET", `/api/mailbox/${a.id}/messages`, undefined, { Authorization: `Bearer ${t}` })).status, 200);
  h.clock.advance(601);
  assert.equal((await h.call("GET", `/api/mailbox/${a.id}/messages`, undefined, { Authorization: `Bearer ${t}` })).status, 401);
});

test("responses are not cached and errors are readable", async () => {
  const h = harness(new MemoryStore());
  const r = await h.call("GET", "/api/health");
  assert.equal(r.headers.get("Cache-Control"), "no-store");
  assert.equal(r.headers.get("X-Content-Type-Options"), "nosniff");
  const nf = await h.call("GET", "/api/nope");
  assert.deepEqual([nf.status, await nf.json()], [404, { error: "no such endpoint" }]);
  const bad = await h.app.request("/api/mailbox/challenge", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{" });
  assert.equal(bad.status, 400);
  assert.equal(mailboxId(Buffer.alloc(32, 9)).length, 64);
});
