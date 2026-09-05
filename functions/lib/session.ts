import type { Env } from "./env";
import { randomToken } from "./crypto";

export const SESSION_COOKIE = "rm_session";
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

export interface SessionUser {
  id: string;
  username: string | null;
  name: string;
  picture: string | null;
}

function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

/** Creates a session row and returns the `Set-Cookie` header value for it. */
export async function createSession(env: Env, userId: string): Promise<string> {
  const id = randomToken(32);
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
  )
    .bind(id, userId, now, now + SESSION_TTL_SECONDS * 1000)
    .run();

  return [
    `${SESSION_COOKIE}=${id}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ].join("; ");
}

export async function destroySession(env: Env, request: Request): Promise<string> {
  const id = readCookie(request, SESSION_COOKIE);
  if (id) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

/** Resolves the request's session cookie to a user, or null. Expired sessions are lazily deleted. */
export async function getSessionUser(env: Env, request: Request): Promise<SessionUser | null> {
  const id = readCookie(request, SESSION_COOKIE);
  if (!id) return null;

  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.name, u.picture, s.expires_at
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.id = ?`,
  )
    .bind(id)
    .first<{ id: string; username: string | null; name: string; picture: string | null; expires_at: number }>();

  if (!row) return null;
  if (row.expires_at < Date.now()) {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
    return null;
  }

  return { id: row.id, username: row.username, name: row.name, picture: row.picture };
}
