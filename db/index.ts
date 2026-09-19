import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

const globalForDb = globalThis as typeof globalThis & { postgresClient?: ReturnType<typeof postgres> };

function getClient() {
  if (globalForDb.postgresClient) return globalForDb.postgresClient;
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is required to connect to PostgreSQL");
  const client = postgres(databaseUrl, {
    max: process.env.NODE_ENV === "production" ? 10 : 1,
    idle_timeout: 20,
    connect_timeout: 10,
  });
  if (process.env.NODE_ENV !== "production") globalForDb.postgresClient = client;
  return client;
}

export function getDb() {
  return drizzle(getClient(), { schema });
}

export async function checkDatabaseConnection() {
  await getClient()`select 1`;
}
