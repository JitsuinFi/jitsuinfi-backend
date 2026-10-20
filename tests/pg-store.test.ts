// The same scenario against Postgres (D-33), only when TEST_DATABASE_URL is set in .env. Rows it
// creates are removed afterwards. Run `npm run migrate` against that database first.
import { test } from "node:test";
import postgres from "postgres";
import { PostgresStore } from "../src/pg-store.ts";
import { fullScenario } from "./flow.ts";

const url = process.env.TEST_DATABASE_URL;
const skip = !url
  ? "TEST_DATABASE_URL is not set"
  : !/^postgres(ql)?:\/\//.test(url)
    ? "TEST_DATABASE_URL is not a postgres:// connection string (a Supabase project https URL is not one)"
    : false;

test("relay scenario against Postgres", { skip }, async () => {
  const store = new PostgresStore(url as string);
  try {
    const { alice, bob } = await fullScenario(store);
    const sql = postgres(url as string, { max: 1, ssl: (url as string).includes("localhost") ? false : "require" });
    await sql`delete from relay_mailboxes where mailbox_id in (${alice.id}, ${bob.id})`;
    await sql.end();
  } finally {
    await store.close();
  }
});
