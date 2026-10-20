// Applies db/*.sql in order to DATABASE_URL. Each file is idempotent (create ... if not exists).
import { readdirSync, readFileSync } from "node:fs";
import postgres from "postgres";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set: put it in .env (never in the repo) or in the Railway variables");
  process.exit(2);
}
const sql = postgres(url, { max: 1, ssl: url.includes("localhost") ? false : "require", onnotice: () => {} });
try {
  const dir = new URL("../db/", import.meta.url);
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
    await sql.unsafe(readFileSync(new URL(f, dir), "utf8"));
    console.log(`applied ${f}`);
  }
} finally {
  await sql.end({ timeout: 5 });
}
