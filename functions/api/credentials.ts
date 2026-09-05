import type { Env } from "../lib/env";
import { getSessionUser } from "../lib/session";
import { encryptSecret } from "../lib/crypto";

const PROVIDERS = new Set(["nvidia", "groq", "atlas"]);

function unauthorized(): Response {
  return new Response(JSON.stringify({ error: "not signed in" }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });
}

/** Which providers this user has connected. Never returns a secret -- only whether one is stored. */
export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) return unauthorized();

  const rows = await env.DB.prepare(
    "SELECT provider, client_id, updated_at FROM credentials WHERE user_id = ?",
  )
    .bind(user.id)
    .all<{ provider: string; client_id: string | null; updated_at: number }>();

  return new Response(JSON.stringify({ connected: rows.results }), {
    headers: { "content-type": "application/json" },
  });
};

/**
 * Save a credential.
 *
 * `nvidia` / `groq`: { provider, apiKey }.
 * `atlas`: { provider: "atlas", clientId, clientSecret } -- an Atlas Service
 * Account pair (OAuth2 client-credentials), not a bare API key. `clientId`
 * is stored in the clear (it identifies the service account, not a secret
 * on its own); `clientSecret` is what gets encrypted.
 */
export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) return unauthorized();

  const body = await request.json<{ provider?: string; apiKey?: string; clientId?: string; clientSecret?: string }>().catch(() => null);
  if (!body || !body.provider || !PROVIDERS.has(body.provider)) {
    return new Response(JSON.stringify({ error: "invalid provider" }), { status: 400, headers: { "content-type": "application/json" } });
  }

  const secret = body.provider === "atlas" ? body.clientSecret : body.apiKey;
  if (!secret || !secret.trim()) {
    return new Response(JSON.stringify({ error: "missing secret" }), { status: 400, headers: { "content-type": "application/json" } });
  }
  if (body.provider === "atlas" && !body.clientId?.trim()) {
    return new Response(JSON.stringify({ error: "missing clientId" }), { status: 400, headers: { "content-type": "application/json" } });
  }

  const { ciphertext, iv } = await encryptSecret(secret.trim(), env.CREDENTIALS_ENCRYPTION_KEY);
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO credentials (user_id, provider, ciphertext, iv, client_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(user_id, provider) DO UPDATE SET
       ciphertext = excluded.ciphertext, iv = excluded.iv,
       client_id = excluded.client_id, updated_at = excluded.updated_at`,
  )
    .bind(user.id, body.provider, ciphertext, iv, body.provider === "atlas" ? body.clientId!.trim() : null, now, now)
    .run();

  return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
};

export const onRequestDelete: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) return unauthorized();

  const provider = new URL(request.url).searchParams.get("provider");
  if (!provider || !PROVIDERS.has(provider)) {
    return new Response(JSON.stringify({ error: "invalid provider" }), { status: 400, headers: { "content-type": "application/json" } });
  }

  await env.DB.prepare("DELETE FROM credentials WHERE user_id = ? AND provider = ?").bind(user.id, provider).run();
  return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
};
