import { eq } from "drizzle-orm";
import { getDb } from "../../../../db";
import { users } from "../../../../db/schema";
import { createSession, ensureInitialAdmin, normalizeUsername, sessionCookie, verifyPassword } from "../../../lib/auth";

export async function POST(request: Request) {
  try {
    await ensureInitialAdmin();
    const body = await request.json() as { username?: unknown; password?: unknown };
    const username = typeof body.username === "string" ? normalizeUsername(body.username) : "";
    const password = typeof body.password === "string" ? body.password : "";
    const [user] = await getDb().select().from(users).where(eq(users.username, username)).limit(1);
    if (!user || !user.isActive || !(await verifyPassword(password, user.passwordHash))) return Response.json({ error: "Неверный логин или пароль" }, { status: 401 });
    const session = await createSession(user.id);
    await getDb().update(users).set({ lastLoginAt: new Date(), updatedAt: new Date() }).where(eq(users.id, user.id));
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "set-cookie": sessionCookie(session.token, session.expiresAt) } });
  } catch (error) {
    console.error("Login failed", error);
    return Response.json({ error: error instanceof SyntaxError ? "Некорректный запрос" : "Авторизация временно недоступна" }, { status: error instanceof SyntaxError ? 400 : 503 });
  }
}
