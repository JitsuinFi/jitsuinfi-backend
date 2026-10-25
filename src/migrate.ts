// Applies db/*.sql in order to DATABASE_URL. Each file is idempotent (create ... if not exists).
import postgres from "postgres";
import { applyMigrations } from "./schema.ts";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set: put it in .env (never in the repo) or in the Railway variables");
  process.exit(2);
}
if (!/^postgres(ql)?:\/\//.test(url)) {
  console.error("DATABASE_URL must be a postgres:// connection string (Supabase: Connect > Session pooler), not the project's https URL");
  process.exit(2);
}
const sql = postgres(url, { max: 1, ssl: url.includes("localhost") ? false : "require", onnotice: () => {} });
try {
  for (const f of await applyMigrations((text) => sql.unsafe(text))) console.log(`applied ${f}`);
} finally {
  await sql.end({ timeout: 5 });
}
