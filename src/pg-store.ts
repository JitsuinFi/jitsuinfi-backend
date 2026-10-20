// Postgres store (Supabase Postgres behind the relay, D-33). Tables: db/001_relay.sql.
import postgres from "postgres";
import type { Challenge, MessageMeta, Store } from "./store.ts";

export class PostgresStore implements Store {
  private sql: postgres.Sql;

  constructor(url: string) {
    this.sql = postgres(url, { max: 5, idle_timeout: 30, ssl: url.includes("localhost") ? false : "require", onnotice: () => {} });
  }

  async addMailbox(id: string, pk: Buffer): Promise<boolean> {
    const r = await this.sql`insert into relay_mailboxes (mailbox_id, mailbox_pk) values (${id}, ${pk}) on conflict do nothing returning mailbox_id`;
    return r.length === 1;
  }
  async mailboxExists(id: string): Promise<boolean> {
    return (await this.sql`select 1 from relay_mailboxes where mailbox_id = ${id}`).length === 1;
  }
  async putChallenge(c: Challenge): Promise<void> {
    await this.sql`insert into relay_challenges (id, mailbox_pk, purpose, eph_secret, eph_public, nonce, expires_at)
      values (${c.id}, ${c.mailboxPk}, ${c.purpose}, ${c.ephSecret}, ${c.ephPublic}, ${c.nonce}, ${c.expiresAt})`;
  }
  async takeChallenge(id: string): Promise<Challenge | undefined> {
    if (!/^[0-9a-f-]{36}$/.test(id)) return undefined;
    const [r] = await this.sql`delete from relay_challenges where id = ${id} returning *`;
    if (!r) return undefined;
    return { id: r.id, mailboxPk: r.mailbox_pk, purpose: r.purpose, ephSecret: r.eph_secret, ephPublic: r.eph_public, nonce: r.nonce, expiresAt: r.expires_at };
  }
  async putToken(hash: string, mailboxId: string, expiresAt: Date): Promise<void> {
    await this.sql`insert into relay_read_tokens (token_hash, mailbox_id, expires_at) values (${hash}, ${mailboxId}, ${expiresAt})`;
  }
  async tokenMailbox(hash: string, now: Date): Promise<string | undefined> {
    const [r] = await this.sql`select mailbox_id from relay_read_tokens where token_hash = ${hash} and expires_at > ${now}`;
    return r?.mailbox_id;
  }
  async countMessages(mailboxId: string, now: Date): Promise<number> {
    const [r] = await this.sql`select count(*)::int as n from relay_messages where mailbox_id = ${mailboxId} and expires_at > ${now}`;
    return r.n;
  }
  async putMessage(mailboxId: string, id: string, ciphertext: Buffer, receivedAt: Date, expiresAt: Date): Promise<void> {
    await this.sql`insert into relay_messages (id, mailbox_id, ciphertext, size, received_at, expires_at)
      values (${id}, ${mailboxId}, ${ciphertext}, ${ciphertext.length}, ${receivedAt}, ${expiresAt})`;
  }
  async listMessages(mailboxId: string, now: Date): Promise<MessageMeta[]> {
    const rows = await this.sql`select id, size, received_at, expires_at from relay_messages
      where mailbox_id = ${mailboxId} and expires_at > ${now} order by received_at, id`;
    return rows.map((r) => ({ id: r.id, size: r.size, receivedAt: r.received_at, expiresAt: r.expires_at }));
  }
  async getMessage(mailboxId: string, id: string, now: Date): Promise<Buffer | undefined> {
    const [r] = await this.sql`select ciphertext from relay_messages where mailbox_id = ${mailboxId} and id = ${id} and expires_at > ${now}`;
    return r?.ciphertext;
  }
  async deleteMessage(mailboxId: string, id: string): Promise<boolean> {
    return (await this.sql`delete from relay_messages where mailbox_id = ${mailboxId} and id = ${id} returning id`).length === 1;
  }
  async purge(now: Date): Promise<number> {
    const r = await this.sql`delete from relay_messages where expires_at <= ${now} returning id`;
    await this.sql`delete from relay_challenges where expires_at <= ${now}`;
    await this.sql`delete from relay_read_tokens where expires_at <= ${now}`;
    return r.length;
  }
  async close(): Promise<void> {
    await this.sql.end({ timeout: 5 });
  }
}
