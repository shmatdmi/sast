import { asc, eq } from "drizzle-orm";
import { getDb } from "../../../db";
import { userAuditLog, userSessions, users } from "../../../db/schema";
import { generateTemporaryPassword, hashPassword, normalizeUsername, requireApiUser, validPassword, validUsername } from "../../lib/auth";

export async function GET(request: Request) {
  const auth = await requireApiUser(request, true); if ("response" in auth) return auth.response;
  return Response.json(await getDb().select({ id: users.id, username: users.username, displayName: users.displayName, role: users.role, isActive: users.isActive, mustChangePassword: users.mustChangePassword, lastLoginAt: users.lastLoginAt, createdAt: users.createdAt }).from(users).orderBy(asc(users.username)));
}

export async function POST(request: Request) {
  const auth = await requireApiUser(request, true); if ("response" in auth) return auth.response;
  const body = await request.json() as Record<string, unknown>;
  const username = typeof body.username === "string" ? normalizeUsername(body.username) : "";
  const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const role = body.role === "admin" ? "admin" : "user";
  if (!validUsername(username) || !displayName || displayName.length > 120 || !validPassword(password)) return Response.json({ error: "Проверьте логин, имя и пароль (минимум 10 символов)" }, { status: 400 });
  try {
    const [created] = await getDb().insert(users).values({ username, displayName, passwordHash: await hashPassword(password), role, mustChangePassword: true }).returning({ id: users.id });
    await getDb().insert(userAuditLog).values({ actorUserId: auth.user.id, targetUserId: created.id, action: "user.created", details: { username, role } });
    return Response.json({ id: created.id }, { status: 201 });
  } catch { return Response.json({ error: "Пользователь с таким логином уже существует" }, { status: 409 }); }
}

export async function PATCH(request: Request) {
  const auth = await requireApiUser(request, true); if ("response" in auth) return auth.response;
  const body = await request.json() as Record<string, unknown>;
  const id = typeof body.id === "string" ? body.id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const [target] = await getDb().select().from(users).where(eq(users.id, id)).limit(1);
  if (!target) return Response.json({ error: "Пользователь не найден" }, { status: 404 });
  if (target.id === auth.user.id && ["block", "delete", "role"].includes(action)) return Response.json({ error: "Нельзя заблокировать, удалить или понизить собственную учётную запись" }, { status: 400 });
  if (target.role === "admin" && target.isActive && (action === "block" || (action === "role" && body.role === "user"))) {
    const activeAdmins = (await getDb().select({ role: users.role, isActive: users.isActive }).from(users)).filter((user) => user.role === "admin" && user.isActive);
    if (activeAdmins.length <= 1) return Response.json({ error: "Нельзя отключить последнего активного администратора" }, { status: 400 });
  }
  let temporaryPassword: string | undefined;
  await getDb().transaction(async (tx) => {
    if (action === "block" || action === "unblock") await tx.update(users).set({ isActive: action === "unblock", updatedAt: new Date() }).where(eq(users.id, id));
    else if (action === "role" && (body.role === "admin" || body.role === "user")) await tx.update(users).set({ role: body.role, updatedAt: new Date() }).where(eq(users.id, id));
    else if (action === "reset-password") { temporaryPassword = generateTemporaryPassword(); await tx.update(users).set({ passwordHash: await hashPassword(temporaryPassword), mustChangePassword: true, updatedAt: new Date() }).where(eq(users.id, id)); }
    else throw new Error("invalid-action");
    if (action !== "unblock") await tx.delete(userSessions).where(eq(userSessions.userId, id));
    await tx.insert(userAuditLog).values({ actorUserId: auth.user.id, targetUserId: id, action: `user.${action}`, details: body.role === "admin" || body.role === "user" ? { role: body.role } : {} });
  }).catch((error) => { if (error instanceof Error && error.message === "invalid-action") return; throw error; });
  if (!['block','unblock','role','reset-password'].includes(action)) return Response.json({ error: "Неизвестное действие" }, { status: 400 });
  return Response.json({ ok: true, temporaryPassword });
}

export async function DELETE(request: Request) {
  const auth = await requireApiUser(request, true); if ("response" in auth) return auth.response;
  const id = new URL(request.url).searchParams.get("id");
  if (!id || id === auth.user.id) return Response.json({ error: "Нельзя удалить собственную учётную запись" }, { status: 400 });
  const [target] = await getDb().select().from(users).where(eq(users.id, id)).limit(1);
  if (!target) return Response.json({ error: "Пользователь не найден" }, { status: 404 });
  if (target.role === "admin" && target.isActive) {
    const activeAdmins = (await getDb().select({ role: users.role, isActive: users.isActive }).from(users)).filter((user) => user.role === "admin" && user.isActive);
    if (activeAdmins.length <= 1) return Response.json({ error: "Нельзя удалить последнего активного администратора" }, { status: 400 });
  }
  await getDb().transaction(async (tx) => { await tx.insert(userAuditLog).values({ actorUserId: auth.user.id, targetUserId: id, action: "user.delete", details: { username: target.username } }); await tx.delete(users).where(eq(users.id, id)); });
  return new Response(null, { status: 204 });
}
