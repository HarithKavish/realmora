import type { Env } from "../../lib/env";
import { getSessionUser } from "../../lib/session";
import { randomToken } from "../../lib/crypto";

function unauthorized(): Response {
  return new Response(JSON.stringify({ error: "not signed in" }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });
}

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) return unauthorized();

  const rows = await env.DB.prepare(
    "SELECT id, name, system_prompt, memory_enabled, created_at, updated_at FROM agents WHERE user_id = ? ORDER BY created_at ASC",
  )
    .bind(user.id)
    .all();

  return new Response(JSON.stringify({ agents: rows.results }), { headers: { "content-type": "application/json" } });
};

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) return unauthorized();

  const body = await request.json<{ name?: string; systemPrompt?: string; memoryEnabled?: boolean }>().catch(() => null);
  const name = body?.name?.trim();
  const systemPrompt = body?.systemPrompt?.trim();
  if (!name || !systemPrompt) {
    return new Response(JSON.stringify({ error: "name and systemPrompt are required" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const id = randomToken(12);
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO agents (id, user_id, name, system_prompt, memory_enabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(id, user.id, name, systemPrompt, body?.memoryEnabled ? 1 : 0, now, now)
    .run();

  return new Response(JSON.stringify({ id, name, systemPrompt, memoryEnabled: !!body?.memoryEnabled }), {
    status: 201,
    headers: { "content-type": "application/json" },
  });
};
