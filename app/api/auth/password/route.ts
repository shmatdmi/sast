import { eq } from "drizzle-orm";
import { getDb } from "../../../../db";
import { userSessions, users } from "../../../../db/schema";
import { hashPassword, requireApiUser, validPassword, verifyPassword } from "../../../lib/auth";

export async function PUT(request: Request) {
  const auth = await requireApiUser(request); if ("response" in auth) return auth.response;
  const body = await request.json() as { currentPassword?: unknown; newPassword?: unknown };
  if (typeof body.currentPassword !== "string" || typeof body.newPassword !== "string" || !validPassword(body.newPassword)) return Response.json({ error: "Новый пароль должен содержать от 10 до 256 символов" }, { status: 400 });
  const [stored] = await getDb().select({ passwordHash: users.passwordHash }).from(users).where(eq(users.id, auth.user.id)).limit(1);
  if (!stored || !(await verifyPassword(body.currentPassword, stored.passwordHash))) return Response.json({ error: "Текущий пароль указан неверно" }, { status: 400 });
  await getDb().transaction(async (tx) => { await tx.update(users).set({ passwordHash: await hashPassword(body.newPassword), mustChangePassword: false, updatedAt: new Date() }).where(eq(users.id, auth.user.id)); await tx.delete(userSessions).where(eq(userSessions.userId, auth.user.id)); });
  return new Response(null, { status: 204 });
}
