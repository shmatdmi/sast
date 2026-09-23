import { createHash, randomBytes } from "node:crypto";
import { and, eq, gt } from "drizzle-orm";
import { getDb } from "../../db";
import { userSessions, users } from "../../db/schema";
import { hashPassword, normalizeUsername, validPassword, validUsername } from "./auth-crypto";
export { generateTemporaryPassword, hashPassword, normalizeUsername, validPassword, validUsername, verifyPassword } from "./auth-crypto";

export const SESSION_COOKIE = "codesentry_session";
const SESSION_AGE_SECONDS = 60 * 60 * 12;
export type AuthUser = { id: string; username: string; displayName: string; role: "admin" | "user"; mustChangePassword: boolean };

const tokenHash = (token: string) => createHash("sha256").update(token).digest("hex");

export async function ensureInitialAdmin() {
  const db = getDb();
  if ((await db.select({ id: users.id }).from(users).limit(1)).length) return;
  const username = normalizeUsername(process.env.INITIAL_ADMIN_USERNAME ?? "admin");
  const password = process.env.INITIAL_ADMIN_PASSWORD ?? "";
  if (!validUsername(username) || !validPassword(password)) throw new Error("INITIAL_ADMIN_PASSWORD must contain at least 10 characters");
  await db.insert(users).values({ username, displayName: "Администратор", passwordHash: await hashPassword(password), role: "admin" }).onConflictDoNothing();
}
export async function createSession(userId: string) { const token = randomBytes(32).toString("base64url"); const expiresAt = new Date(Date.now() + SESSION_AGE_SECONDS * 1000); await getDb().insert(userSessions).values({ userId, tokenHash: tokenHash(token), expiresAt }); return { token, expiresAt }; }
function cookieValue(cookieHeader: string | null, name: string) { for (const part of (cookieHeader ?? "").split(";")) { const [key, ...value] = part.trim().split("="); if (key === name) return decodeURIComponent(value.join("=")); } return null; }
export async function getUserFromCookie(cookieHeader: string | null): Promise<AuthUser | null> {
  const token = cookieValue(cookieHeader, SESSION_COOKIE); if (!token) return null;
  const [row] = await getDb().select({ id: users.id, username: users.username, displayName: users.displayName, role: users.role, mustChangePassword: users.mustChangePassword, isActive: users.isActive }).from(userSessions).innerJoin(users, eq(userSessions.userId, users.id)).where(and(eq(userSessions.tokenHash, tokenHash(token)), gt(userSessions.expiresAt, new Date()))).limit(1);
  if (!row?.isActive || (row.role !== "admin" && row.role !== "user")) return null;
  return { id: row.id, username: row.username, displayName: row.displayName, role: row.role, mustChangePassword: row.mustChangePassword };
}
export async function requireApiUser(request: Request, admin = false) { const user = await getUserFromCookie(request.headers.get("cookie")); if (!user) return { response: Response.json({ error: "Требуется авторизация" }, { status: 401 }) } as const; if (admin && user.role !== "admin") return { response: Response.json({ error: "Недостаточно прав" }, { status: 403 }) } as const; return { user } as const; }
export function sessionCookie(token: string, expiresAt: Date) { return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Expires=${expiresAt.toUTCString()}${process.env.AUTH_COOKIE_SECURE === "true" ? "; Secure" : ""}`; }
export function expiredSessionCookie() { return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`; }
