import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import { getDb } from "../../../../db";
import { userSessions } from "../../../../db/schema";
import { expiredSessionCookie, SESSION_COOKIE } from "../../../lib/auth";

export async function POST(request: Request) {
  const token = (request.headers.get("cookie") ?? "").split(";").map((part) => part.trim()).find((part) => part.startsWith(`${SESSION_COOKIE}=`))?.slice(SESSION_COOKIE.length + 1);
  if (token) await getDb().delete(userSessions).where(eq(userSessions.tokenHash, createHash("sha256").update(decodeURIComponent(token)).digest("hex")));
  return new Response(null, { status: 204, headers: { "set-cookie": expiredSessionCookie() } });
}
