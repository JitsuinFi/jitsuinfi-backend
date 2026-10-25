// The relay's tables: db/*.sql, applied in name order. Each file is idempotent (create ... if not
// exists), so they run before every deploy (`npm run migrate`, railway.json) and again when the
// relay starts on Postgres: a deploy whose pre-deploy step did not run cannot serve an older
// schema (HNK-34 E2E: GET /state answered 500 because relay_state was missing in production).
import { readdirSync, readFileSync } from "node:fs";

export const MIGRATIONS = new URL("../db/", import.meta.url);

/** The migration files in the order they apply. */
export function migrationFiles(dir: URL = MIGRATIONS): string[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
}

/** Applies every migration through `run` (one SQL text per file); returns the files applied. */
export async function applyMigrations(run: (sqlText: string) => Promise<unknown>, dir: URL = MIGRATIONS): Promise<string[]> {
  const files = migrationFiles(dir);
  for (const f of files) await run(readFileSync(new URL(f, dir), "utf8"));
  return files;
}
