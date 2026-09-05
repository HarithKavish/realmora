import type { Env } from "../../lib/env";
import { exchangeCodeForToken, fetchProfile } from "../../lib/ecosystem";
import { createSession } from "../../lib/session";

function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie") ?? "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

const clearTempCookies = [
  "rm_oauth_verifier=; Path=/api/auth/callback; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
  "rm_oauth_state=; Path=/api/auth/callback; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
];

function failure(reason: string): Response {
  return new Response(`Sign-in failed: ${reason}`, {
    status: 400,
    headers: [["content-type", "text/plain"], ...clearTempCookies.map((c) => ["Set-Cookie", c] as const)],
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const expectedState = readCookie(request, "rm_oauth_state");
  const verifier = readCookie(request, "rm_oauth_verifier");

  if (!code || !state || !expectedState || state !== expectedState || !verifier) {
    return failure("invalid or expired sign-in attempt -- please try again");
  }

  const token = await exchangeCodeForToken({
    code,
    codeVerifier: verifier,
    redirectUri: `${url.origin}/api/auth/callback`,
    clientSecret: env.OAUTH_SECRET_REALMORA,
  });
  if (!token) return failure("could not exchange the authorization code");

  const profile = await fetchProfile(token.accessToken);
  if (!profile) return failure("could not read the signed-in profile");

  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO users (id, username, name, picture, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET username = excluded.username, name = excluded.name,
       picture = excluded.picture, updated_at = excluded.updated_at`,
  )
    .bind(profile.sub, profile.preferred_username, profile.name, profile.picture, now, now)
    .run();

  const sessionCookie = await createSession(env, profile.sub);

  return new Response(null, {
    status: 302,
    headers: [
      ["Location", "/"],
      ["Set-Cookie", sessionCookie],
      ...clearTempCookies.map((c) => ["Set-Cookie", c] as const),
    ],
  });
};
