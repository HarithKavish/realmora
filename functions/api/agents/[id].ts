import type { Env } from "../../lib/env";
import { getSessionUser } from "../../lib/session";

function unauthorized(): Response {
  return new Response(JSON.stringify({ error: "not signed in" }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });
}

async function ownsAgent(env: Env, userId: string, agentId: string): Promise<boolean> {
  const row = await env.DB.prepare("SELECT 1 FROM agents WHERE id = ? AND user_id = ?").bind(agentId, userId).first();
  return !!row;
}

export const onRequestPatch: PagesFunction<Env> = async ({ request, env, params }) => {
  const user = await getSessionUser(env, request);
  if (!user) return unauthorized();

  const agentId = params.id as string;
  if (!(await ownsAgent(env, user.id, agentId))) {
    return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
  }

  const body = await request.json<{ name?: string; systemPrompt?: string; memoryEnabled?: boolean }>().catch(() => null);
  if (!body) return new Response(JSON.stringify({ error: "invalid body" }), { status: 400, headers: { "content-type": "application/json" } });

  const sets: string[] = [];
  const values: unknown[] = [];
  if (body.name?.trim()) { sets.push("name = ?"); values.push(body.name.trim()); }
  if (body.systemPrompt?.trim()) { sets.push("system_prompt = ?"); values.push(body.systemPrompt.trim()); }
  if (typeof body.memoryEnabled === "boolean") { sets.push("memory_enabled = ?"); values.push(body.memoryEnabled ? 1 : 0); }
  if (sets.length === 0) {
    return new Response(JSON.stringify({ error: "nothing to update" }), { status: 400, headers: { "content-type": "application/json" } });
  }
  sets.push("updated_at = ?");
  values.push(Date.now());

  await env.DB.prepare(`UPDATE agents SET ${sets.join(", ")} WHERE id = ?`).bind(...values, agentId).run();
  return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
};

export const onRequestDelete: PagesFunction<Env> = async ({ request, env, params }) => {
  const user = await getSessionUser(env, request);
  if (!user) return unauthorized();

  const agentId = params.id as string;
  if (!(await ownsAgent(env, user.id, agentId))) {
    return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: { "content-type": "application/json" } });
  }

  await env.DB.prepare("DELETE FROM agents WHERE id = ?").bind(agentId).run();
  return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
};
