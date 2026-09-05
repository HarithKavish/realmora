import type { Env } from "../lib/env";
import { getSessionUser } from "../lib/session";
import { decryptSecret } from "../lib/crypto";

/**
 * Provider fallback chain -- mirrors the reasoning behind Jarvis/Hermes's
 * "voice" tier (lowest latency), just without the tool-calling gateway
 * around it: a friend's agent is a system prompt plus a completion call.
 *
 * Groq leads on latency but free-tier accounts hit a small daily token cap
 * that can take the whole account down mid-conversation; NVIDIA NIM is the
 * fallback because it is a completely separate quota, not because it's
 * faster.
 */
const CANDIDATES = [
  { provider: "groq", baseUrl: "https://api.groq.com/openai/v1", model: "openai/gpt-oss-20b" },
  { provider: "nvidia", baseUrl: "https://integrate.api.nvidia.com/v1", model: "nvidia/nemotron-3-nano-30b-a3b" },
] as const;

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

async function loadKey(env: Env, userId: string, provider: string): Promise<string | null> {
  const row = await env.DB.prepare("SELECT ciphertext, iv FROM credentials WHERE user_id = ? AND provider = ?")
    .bind(userId, provider)
    .first<{ ciphertext: string; iv: string }>();
  if (!row) return null;
  return decryptSecret(row, env.CREDENTIALS_ENCRYPTION_KEY);
}

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) {
    return new Response(JSON.stringify({ error: "not signed in" }), { status: 401, headers: { "content-type": "application/json" } });
  }

  const body = await request.json<{ agentId?: string; messages?: ChatMessage[] }>().catch(() => null);
  if (!body?.agentId || !Array.isArray(body.messages) || body.messages.length === 0) {
    return new Response(JSON.stringify({ error: "agentId and messages are required" }), {
      status: 400,
      headers: { "content-type": "application/json" },
    });
  }

  const agent = await env.DB.prepare("SELECT system_prompt FROM agents WHERE id = ? AND user_id = ?")
    .bind(body.agentId, user.id)
    .first<{ system_prompt: string }>();
  if (!agent) {
    return new Response(JSON.stringify({ error: "agent not found" }), { status: 404, headers: { "content-type": "application/json" } });
  }

  const keys = new Map<string, string>();
  for (const candidate of CANDIDATES) {
    const key = await loadKey(env, user.id, candidate.provider);
    if (key) keys.set(candidate.provider, key);
  }
  if (keys.size === 0) {
    return new Response(
      JSON.stringify({ error: "no provider connected -- add an NVIDIA or Groq API key in settings" }),
      { status: 400, headers: { "content-type": "application/json" } },
    );
  }

  const payload = {
    stream: true,
    messages: [{ role: "system", content: agent.system_prompt }, ...body.messages],
  };

  let lastError = "";
  for (const candidate of CANDIDATES) {
    const key = keys.get(candidate.provider);
    if (!key) continue;

    try {
      const upstream = await fetch(`${candidate.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({ ...payload, model: candidate.model }),
      });

      // 429 (Groq's daily/TPM cap) and 5xx are exactly the failures the
      // fallback exists for; anything else (e.g. a malformed key -> 401)
      // is the user's own config and should surface, not be swallowed by a
      // silent fallback that only muddies which provider is misconfigured.
      if (upstream.status === 429 || upstream.status >= 500) {
        lastError = `${candidate.provider}: HTTP ${upstream.status}`;
        continue;
      }
      if (!upstream.ok || !upstream.body) {
        const detail = await upstream.text().catch(() => "");
        return new Response(JSON.stringify({ error: `${candidate.provider} rejected the request`, detail }), {
          status: upstream.status,
          headers: { "content-type": "application/json" },
        });
      }

      // Pass the OpenAI-compatible SSE stream straight through.
      return new Response(upstream.body, {
        headers: {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          "x-realmora-provider": candidate.provider,
        },
      });
    } catch (error) {
      lastError = `${candidate.provider}: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  return new Response(JSON.stringify({ error: "every connected provider failed", detail: lastError }), {
    status: 502,
    headers: { "content-type": "application/json" },
  });
};
