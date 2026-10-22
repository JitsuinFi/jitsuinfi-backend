// Relay settings from the environment (.env locally, Railway variables in production).
// The database credential (DATABASE_URL) never appears in the repo, the vault or a log (D-33).

/** Largest relay message plaintext: "JTSM" ‖ version ‖ header length (9 bytes), a 64 KiB header
 *  and two 2 MiB PDFs (jitsuinfi-frontend src/lib/relay-message.ts). */
export const MAX_PLAINTEXT = 9 + 64 * 1024 + 2 * 2 * 1024 * 1024;
/** Sealed box overhead: ephemeral X25519 key (32) and Poly1305 tag (16). */
export const SEAL_OVERHEAD = 48;
export const MAX_CIPHERTEXT = MAX_PLAINTEXT + SEAL_OVERHEAD;
/** Largest mailbox state (HNK-25.T2): the owner's own sealed backup, such as a buyer's history
 *  chain (64 certificates of 277 bytes in base64url JSON fit with room to spare). */
export const MAX_STATE = 64 * 1024 + SEAL_OVERHEAD;

export interface Config {
  port: number;
  databaseUrl: string | undefined;
  retentionDays: number;
  maxMessagesPerMailbox: number;
  challengeTtlSeconds: number;
  readTokenTtlSeconds: number;
}

function int(name: string, fallback: number, min: number): number {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min) throw new Error(`${name} must be an integer of at least ${min}`);
  return n;
}

function postgresUrl(v: string | undefined): string | undefined {
  if (!v) return undefined;
  if (!/^postgres(ql)?:\/\//.test(v)) throw new Error("DATABASE_URL must be a postgres:// connection string (Supabase: Connect > Session pooler)");
  return v;
}

export function loadConfig(): Config {
  return {
    port: int("PORT", 8787, 1),
    databaseUrl: postgresUrl(process.env.DATABASE_URL),
    retentionDays: int("RETENTION_DAYS", 30, 1),
    maxMessagesPerMailbox: int("MAX_MESSAGES_PER_MAILBOX", 200, 1),
    challengeTtlSeconds: int("CHALLENGE_TTL_SECONDS", 120, 10),
    readTokenTtlSeconds: int("READ_TOKEN_TTL_SECONDS", 600, 30),
  };
}
