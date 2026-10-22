# jitsuinfi-backend

Relay for **JitsuinFi**: encrypted mailboxes that carry deal documents between supplier, buyer and financier (HNK-23, vault D-33). The relay stores only what it must: each mailbox's X25519 key and id, opaque sealed messages with their size and times, one-time challenges and short read tokens. It never sees a document, a key or an IP address in its tables.

The browser reaches it as `/api/*` on the web app's own origin (Vercel rewrite, HNK-23.T6), so the app's CSP stays `connect-src 'self'`. The database is Supabase Postgres, reached only from this server (D-33).

## Protocol

- `mailbox_id = BLAKE2b-512("JitsuinMailboxId_v1\n" ‖ mailbox_pk)[0..32]`, hex. The relay computes it from the key, so its id always matches the client's.
- **Ownership proof** (register, read): the relay makes a one-time ephemeral X25519 key `e` and a 32-byte nonce. The owner answers
  `BLAKE2b-512("JitsuinMailboxProof_v1\n" ‖ purpose ‖ 0x00 ‖ X25519(mailbox_secret, e_pk) ‖ nonce ‖ mailbox_pk)[0..32]`.
  Only the holder of the mailbox secret can compute it; knowing `mailbox_id` or `mailbox_pk` is not enough. Low-order keys are refused.
- Messages are sealed boxes to the recipient's `mailbox_pk` (made in the browser by jitsuin-wasm, HNK-23.T2), at most `9 + 64 KiB + 2 × 2 MiB` plaintext plus 48 bytes. Their format and signatures (`JTSM`, jitsuinfi-frontend `src/lib/relay-message.ts`) are checked by the recipient, not here.

| Method | Path | Body | Answer |
|---|---|---|---|
| POST | `/api/mailbox/challenge` | `{mailbox_pk, purpose: "register" \| "read"}` | `{challenge_id, eph_pk, nonce, expires_at}` (120 s, single use) |
| POST | `/api/mailbox` | `{mailbox_pk, challenge_id, proof}` | `201 {mailbox_id, created: true}`, or `200` when it exists |
| POST | `/api/mailbox/:id/read` | `{challenge_id, proof}` | `{token, expires_at}` (10 min) |
| POST | `/api/mailbox/:id/messages` | sealed box, `application/octet-stream` | `202 {message_id, expires_at}`; anyone may send |
| GET | `/api/mailbox/:id/messages` | `Authorization: Bearer <token>` | `{messages: [{id, size, received_at, expires_at}]}` |
| GET | `/api/mailbox/:id/messages/:mid` | Bearer | the sealed box |
| DELETE | `/api/mailbox/:id/messages/:mid` | Bearer | `204` |
| PUT | `/api/mailbox/:id/state` | Bearer, sealed box (`application/octet-stream`, at most 64 KiB + 48) | `{updated_at}`; replaces the owner's state |
| GET | `/api/mailbox/:id/state` | Bearer | the owner's sealed state, or `404` when none was saved |

Messages expire after `RETENTION_DAYS` (30); a mailbox holds at most `MAX_MESSAGES_PER_MAILBOX` (200) unread messages. Errors are `{error}` with a readable sentence.

The **state** (HNK-25.T2) is one sealed blob per mailbox that only its owner writes and reads, kept until the owner replaces it: the buyer's history chain, sealed in the browser to the buyer's own mailbox key, so a second device signed in with the same passkey gets it back. The relay sees its size and time only. It cannot forge a chain (every certificate is signed by the buyer's identity key and links the previous one); it can only withhold or roll it back, which the browser detects against its own copy and the next certificate's tag on the board.

## Run

Node 22.18 or later (runs TypeScript directly).

```bash
npm install
cp .env.example .env   # then fill DATABASE_URL yourself; never paste it in chat or commit it
npm run migrate        # creates the relay_* tables in that database
npm start              # :8787; without DATABASE_URL it keeps everything in memory
```

`npm test` runs the API against an in-memory store, and against Postgres when `TEST_DATABASE_URL` is set. `npm run typecheck` checks the types.

## Deploy on Railway (HNK-23.T5, after approval)

`railway.json` builds with Railpack on Node 24 (`.node-version`), runs `npm run migrate` before each deploy (idempotent), starts with `npm start` and checks `/api/health`.

1. Railway: New project → Deploy from GitHub repo → `JitsuinFi/jitsuinfi-backend` (give the Railway GitHub app access to this private repo), branch `main`.
2. Variables: `DATABASE_URL` = the Supabase **Session pooler** URI (below). `PORT` is set by Railway. Optional: `RETENTION_DAYS`, `MAX_MESSAGES_PER_MAILBOX`, `CHALLENGE_TTL_SECONDS`, `READ_TOKEN_TTL_SECONDS`.
3. Networking → Generate domain. The web app reaches it through a Vercel rewrite of `/api/*` (HNK-23.T6), never directly.

`DATABASE_URL` from Supabase: Connect → Connection string → URI → Method **Session pooler**:
`postgresql://postgres.<project-ref>:<database-password>@aws-0-<region>.pooler.supabase.com:5432/postgres`.
Session pooler, because the direct connection is IPv6 only and Railway connects over IPv4; port 5432 (session mode), because `postgres` uses prepared statements. The password is the database password (Project Settings → Database), not an API key. No Supabase API keys (anon, publishable, secret, service role) are used: the relay talks to Postgres only, and the browser never talks to Supabase (D-33).

Status: in development for ZECATHON 2026, on Zcash testnet.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option. Unless you explicitly state otherwise, any contribution you submit for inclusion in this work, as defined in the Apache-2.0 license, is dual licensed as above, without any additional terms or conditions.
