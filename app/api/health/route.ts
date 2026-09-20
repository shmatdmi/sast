import { checkDatabaseConnection } from "../../../db";
import { appVersion } from "../../lib/version";

export async function GET() {
  try {
    await checkDatabaseConnection();
    return Response.json({ status: "ok", database: "connected", version: appVersion });
  } catch (error) {
    console.error("Database health check failed", error);
    return Response.json({ status: "error", database: "unavailable", version: appVersion }, { status: 503 });
  }
}
