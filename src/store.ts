// What the relay keeps (D-33, threat model "Relay" rows): mailbox keys and ids, opaque ciphertext
// with its size and times, one-time challenges and short read tokens. No IP, no sender, no content.

import type { Purpose } from "./crypto.ts";

export interface Challenge {
  id: string;
  mailboxPk: Buffer;
  purpose: Purpose;
  ephSecret: Buffer;
  ephPublic: Buffer;
  nonce: Buffer;
  expiresAt: Date;
}

export interface MessageMeta {
  id: string;
  size: number;
  receivedAt: Date;
  expiresAt: Date;
}

export interface Store {
  /** Registers a mailbox; true when it is new, false when it already existed. */
  addMailbox(id: string, pk: Buffer): Promise<boolean>;
  mailboxExists(id: string): Promise<boolean>;
  putChallenge(c: Challenge): Promise<void>;
  /** Removes and returns the challenge: a challenge works once. */
  takeChallenge(id: string): Promise<Challenge | undefined>;
  putToken(hash: string, mailboxId: string, expiresAt: Date): Promise<void>;
  tokenMailbox(hash: string, now: Date): Promise<string | undefined>;
  countMessages(mailboxId: string, now: Date): Promise<number>;
  putMessage(mailboxId: string, id: string, ciphertext: Buffer, receivedAt: Date, expiresAt: Date): Promise<void>;
  listMessages(mailboxId: string, now: Date): Promise<MessageMeta[]>;
  getMessage(mailboxId: string, id: string, now: Date): Promise<Buffer | undefined>;
  deleteMessage(mailboxId: string, id: string): Promise<boolean>;
  /** The owner's sealed state, one per mailbox, replaced on each write and never expired. */
  putState(mailboxId: string, ciphertext: Buffer, updatedAt: Date): Promise<void>;
  getState(mailboxId: string): Promise<{ ciphertext: Buffer; updatedAt: Date } | undefined>;
  /** Drops expired messages, challenges and tokens; returns how many messages went. */
  purge(now: Date): Promise<number>;
  close(): Promise<void>;
}

/** In-memory store, for tests and for local runs without DATABASE_URL. */
export class MemoryStore implements Store {
  private mailboxes = new Map<string, Buffer>();
  private challenges = new Map<string, Challenge>();
  private tokens = new Map<string, { mailboxId: string; expiresAt: Date }>();
  private messages = new Map<string, Map<string, { ciphertext: Buffer; meta: MessageMeta }>>();
  private states = new Map<string, { ciphertext: Buffer; updatedAt: Date }>();

  async addMailbox(id: string, pk: Buffer): Promise<boolean> {
    if (this.mailboxes.has(id)) return false;
    this.mailboxes.set(id, Buffer.from(pk));
    this.messages.set(id, new Map());
    return true;
  }
  async mailboxExists(id: string): Promise<boolean> {
    return this.mailboxes.has(id);
  }
  async putChallenge(c: Challenge): Promise<void> {
    this.challenges.set(c.id, c);
  }
  async takeChallenge(id: string): Promise<Challenge | undefined> {
    const c = this.challenges.get(id);
    this.challenges.delete(id);
    return c;
  }
  async putToken(hash: string, mailboxId: string, expiresAt: Date): Promise<void> {
    this.tokens.set(hash, { mailboxId, expiresAt });
  }
  async tokenMailbox(hash: string, now: Date): Promise<string | undefined> {
    const t = this.tokens.get(hash);
    return t && t.expiresAt > now ? t.mailboxId : undefined;
  }
  async countMessages(mailboxId: string, now: Date): Promise<number> {
    return [...(this.messages.get(mailboxId)?.values() ?? [])].filter((m) => m.meta.expiresAt > now).length;
  }
  async putMessage(mailboxId: string, id: string, ciphertext: Buffer, receivedAt: Date, expiresAt: Date): Promise<void> {
    this.messages.get(mailboxId)?.set(id, { ciphertext: Buffer.from(ciphertext), meta: { id, size: ciphertext.length, receivedAt, expiresAt } });
  }
  async listMessages(mailboxId: string, now: Date): Promise<MessageMeta[]> {
    return [...(this.messages.get(mailboxId)?.values() ?? [])]
      .map((m) => m.meta)
      .filter((m) => m.expiresAt > now)
      .sort((a, b) => a.receivedAt.getTime() - b.receivedAt.getTime());
  }
  async getMessage(mailboxId: string, id: string, now: Date): Promise<Buffer | undefined> {
    const m = this.messages.get(mailboxId)?.get(id);
    return m && m.meta.expiresAt > now ? m.ciphertext : undefined;
  }
  async deleteMessage(mailboxId: string, id: string): Promise<boolean> {
    return this.messages.get(mailboxId)?.delete(id) ?? false;
  }
  async putState(mailboxId: string, ciphertext: Buffer, updatedAt: Date): Promise<void> {
    this.states.set(mailboxId, { ciphertext: Buffer.from(ciphertext), updatedAt });
  }
  async getState(mailboxId: string): Promise<{ ciphertext: Buffer; updatedAt: Date } | undefined> {
    return this.states.get(mailboxId);
  }
  async purge(now: Date): Promise<number> {
    let n = 0;
    for (const box of this.messages.values()) {
      for (const [id, m] of box) if (m.meta.expiresAt <= now) (box.delete(id), n++);
    }
    for (const [id, c] of this.challenges) if (c.expiresAt <= now) this.challenges.delete(id);
    for (const [h, t] of this.tokens) if (t.expiresAt <= now) this.tokens.delete(h);
    return n;
  }
  async close(): Promise<void> {}
}
