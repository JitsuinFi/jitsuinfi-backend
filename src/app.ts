// Relay HTTP API (HNK-23.T3, T4). The browser reaches it as /api/* on the web app's own origin
// through a Vercel rewrite (HNK-23.T6), so the app's CSP stays connect-src 'self'.
//
//   POST   /api/mailbox/challenge               {mailbox_pk, purpose}  → one-time challenge
//   POST   /api/mailbox                         {mailbox_pk, challenge_id, proof} → mailbox_id
//   POST   /api/mailbox/:id/read                {challenge_id, proof}  → short read token
//   POST   /api/mailbox/:id/messages            sealed box (octet-stream) → message id
//   GET    /api/mailbox/:id/messages            Bearer token → [{id, size, received_at}]
//   GET    /api/mailbox/:id/messages/:mid       Bearer token → sealed box
//   DELETE /api/mailbox/:id/messages/:mid       Bearer token → removed after reading
//   PUT    /api/mailbox/:id/state               Bearer token, sealed box → the owner's state replaced
//   GET    /api/mailbox/:id/state               Bearer token → the owner's sealed state
//
// Anyone who knows a mailbox_id can drop a message in it (that is how parties reach each other);
// only the mailbox owner can list or fetch. Messages are opaque here: their meaning and their
// signatures are checked in the recipient's browser (relay-message.ts).
import { randomUUID } from "node:crypto";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { MAX_CIPHERTEXT, MAX_STATE, SEAL_OVERHEAD, type Config } from "./config.ts";
import { BadRequest, ephemeral, fromHex, mailboxId, proofTag, randomBytes, randomToken, sameBytes, tokenHash, x25519, type Purpose } from "./crypto.ts";
import type { Store } from "./store.ts";

class HttpError extends Error {
  readonly status: 401 | 403 | 404 | 409 | 413 | 429;
  constructor(status: 401 | 403 | 404 | 409 | 413 | 429, message: string) {
    super(message);
    this.status = status;
  }
}

const iso = (d: Date) => d.toISOString();

/** Postgres "undefined_table" (42P01): the schema is behind this code (a migration did not run). */
const missingTable = (err: Error): boolean => (err as { code?: unknown }).code === "42P01";

export function createApp(store: Store, cfg: Config, now: () => Date = () => new Date()): Hono {
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    c.header("Cache-Control", "no-store");
    c.header("X-Content-Type-Options", "nosniff");
    c.header("Referrer-Policy", "no-referrer");
  });

  app.onError((err, c) => {
    if (err instanceof BadRequest) return c.json({ error: err.message }, 400);
    if (err instanceof HttpError) return c.json({ error: err.message }, err.status);
    if (err instanceof SyntaxError) return c.json({ error: "the request body is not valid JSON" }, 400);
    if (missingTable(err)) {
      console.error("relay error:", err.message, "(run npm run migrate)");
      return c.json({ error: "the relay's database is not set up for this request yet; try again later" }, 503);
    }
    console.error("relay error:", err instanceof Error ? err.message : err);
    return c.json({ error: "the relay could not handle this request" }, 500);
  });

  app.notFound((c) => c.json({ error: "no such endpoint" }, 404));

  app.get("/api/health", (c) => c.json({ ok: true }));

  const json = async (c: Context): Promise<Record<string, unknown>> => {
    const body = await c.req.json();
    if (typeof body !== "object" || body === null || Array.isArray(body)) throw new BadRequest("the request body must be a JSON object");
    return body as Record<string, unknown>;
  };

  const purposeOf = (v: unknown): Purpose => {
    if (v !== "register" && v !== "read") throw new BadRequest('purpose must be "register" or "read"');
    return v;
  };

  /** Checks a proof against its one-time challenge and returns the proven mailbox key. */
  const proven = async (body: Record<string, unknown>, purpose: Purpose, pk?: Buffer): Promise<Buffer> => {
    if (typeof body.challenge_id !== "string") throw new BadRequest("challenge_id is missing");
    const proof = fromHex(body.proof as string, 32, "proof");
    const ch = await store.takeChallenge(body.challenge_id);
    if (!ch || ch.expiresAt <= now()) throw new HttpError(403, "the challenge is unknown, used or expired; ask for a new one");
    if (ch.purpose !== purpose) throw new HttpError(403, `this challenge is for "${ch.purpose}", not "${purpose}"`);
    if (pk && !sameBytes(pk, ch.mailboxPk)) throw new HttpError(403, "this challenge was made for another mailbox key");
    const expected = proofTag(purpose, x25519(ch.ephSecret, ch.ephPublic, ch.mailboxPk), ch.nonce, ch.mailboxPk);
    if (!sameBytes(proof, expected)) throw new HttpError(403, "the proof does not match: this key's owner did not answer");
    return ch.mailboxPk;
  };

  app.post("/api/mailbox/challenge", async (c) => {
    const body = await json(c);
    const pk = fromHex(body.mailbox_pk as string, 32, "mailbox_pk");
    const purpose = purposeOf(body.purpose);
    const e = ephemeral();
    x25519(e.secret, e.public, pk); // refuses a low-order key before any state is kept
    const id = randomUUID();
    const nonce = randomBytes(32);
    const expiresAt = new Date(now().getTime() + cfg.challengeTtlSeconds * 1000);
    await store.putChallenge({ id, mailboxPk: pk, purpose, ephSecret: e.secret, ephPublic: e.public, nonce, expiresAt });
    return c.json({ challenge_id: id, purpose, eph_pk: e.public.toString("hex"), nonce: nonce.toString("hex"), expires_at: iso(expiresAt) });
  });

  app.post("/api/mailbox", async (c) => {
    const body = await json(c);
    const pk = fromHex(body.mailbox_pk as string, 32, "mailbox_pk");
    await proven(body, "register", pk);
    const id = mailboxId(pk);
    const created = await store.addMailbox(id, pk);
    return c.json({ mailbox_id: id, created }, created ? 201 : 200);
  });

  const mailboxParam = async (c: Context): Promise<string> => {
    const id = c.req.param("id") ?? "";
    fromHex(id, 32, "mailbox_id");
    if (!(await store.mailboxExists(id))) throw new HttpError(404, "no mailbox with this id");
    return id;
  };

  app.post("/api/mailbox/:id/read", async (c) => {
    const id = await mailboxParam(c);
    const pk = await proven(await json(c), "read");
    if (mailboxId(pk) !== id) throw new HttpError(403, "this proof is for another mailbox");
    const token = randomToken();
    const expiresAt = new Date(now().getTime() + cfg.readTokenTtlSeconds * 1000);
    await store.putToken(tokenHash(token), id, expiresAt);
    return c.json({ token, expires_at: iso(expiresAt) });
  });

  const authorized = async (c: Context): Promise<string> => {
    const id = await mailboxParam(c);
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(c.req.header("Authorization") ?? "");
    const owner = m ? await store.tokenMailbox(tokenHash(m[1]), now()) : undefined;
    if (owner !== id) throw new HttpError(401, "reading a mailbox needs a read token from its owner");
    return id;
  };

  app.post(
    "/api/mailbox/:id/messages",
    bodyLimit({ maxSize: MAX_CIPHERTEXT, onError: (c) => c.json({ error: `a message is at most ${MAX_CIPHERTEXT} bytes sealed (two 2 MiB PDFs and a 64 KiB header)` }, 413) }),
    async (c) => {
      const id = await mailboxParam(c);
      if ((c.req.header("Content-Type") ?? "").split(";")[0].trim() !== "application/octet-stream") {
        throw new BadRequest("send the sealed message as application/octet-stream");
      }
      const ciphertext = Buffer.from(await c.req.arrayBuffer());
      if (ciphertext.length <= SEAL_OVERHEAD) throw new BadRequest("this is not a sealed message");
      const t = now();
      if ((await store.countMessages(id, t)) >= cfg.maxMessagesPerMailbox) throw new HttpError(429, "this mailbox is full; its owner must read and remove messages first");
      const mid = randomUUID();
      const expiresAt = new Date(t.getTime() + cfg.retentionDays * 86_400_000);
      await store.putMessage(id, mid, ciphertext, t, expiresAt);
      return c.json({ message_id: mid, expires_at: iso(expiresAt) }, 202);
    },
  );

  app.get("/api/mailbox/:id/messages", async (c) => {
    const id = await authorized(c);
    const list = await store.listMessages(id, now());
    return c.json({ messages: list.map((m) => ({ id: m.id, size: m.size, received_at: iso(m.receivedAt), expires_at: iso(m.expiresAt) })) });
  });

  const messageParam = (c: Context): string => {
    const mid = c.req.param("mid") ?? "";
    if (!/^[0-9a-f-]{36}$/.test(mid)) throw new BadRequest("message id must be a UUID");
    return mid;
  };

  app.get("/api/mailbox/:id/messages/:mid", async (c) => {
    const id = await authorized(c);
    const body = await store.getMessage(id, messageParam(c), now());
    if (!body) throw new HttpError(404, "no such message (removed or expired)");
    return c.body(new Uint8Array(body), 200, { "Content-Type": "application/octet-stream" });
  });

  app.delete("/api/mailbox/:id/messages/:mid", async (c) => {
    const id = await authorized(c);
    if (!(await store.deleteMessage(id, messageParam(c)))) throw new HttpError(404, "no such message (removed or expired)");
    return c.body(null, 204);
  });

  // HNK-25.T2 (BL-D26-03): one sealed state per mailbox that only its owner writes and reads, so a
  // buyer's history chain follows its passkey to another device. The relay cannot read it; it can
  // only withhold or roll it back, which the browser detects against its own copy and the board.
  app.put(
    "/api/mailbox/:id/state",
    bodyLimit({ maxSize: MAX_STATE, onError: (c) => c.json({ error: `the state is at most ${MAX_STATE} bytes sealed` }, 413) }),
    async (c) => {
      const id = await authorized(c);
      if ((c.req.header("Content-Type") ?? "").split(";")[0].trim() !== "application/octet-stream") {
        throw new BadRequest("send the sealed state as application/octet-stream");
      }
      const ciphertext = Buffer.from(await c.req.arrayBuffer());
      if (ciphertext.length <= SEAL_OVERHEAD) throw new BadRequest("this is not a sealed state");
      const t = now();
      await store.putState(id, ciphertext, t);
      return c.json({ updated_at: iso(t) });
    },
  );

  app.get("/api/mailbox/:id/state", async (c) => {
    const id = await authorized(c);
    const s = await store.getState(id);
    if (!s) throw new HttpError(404, "this mailbox has no saved state");
    return c.body(new Uint8Array(s.ciphertext), 200, { "Content-Type": "application/octet-stream", "Last-Modified": s.updatedAt.toUTCString() });
  });

  return app;
}
