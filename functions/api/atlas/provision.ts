import type { Env } from "../../lib/env";
import { getSessionUser } from "../../lib/session";
import { advanceAtlasProvisioning } from "../../lib/atlas";

/**
 * Advance-and-report Atlas provisioning for the signed-in user.
 *
 * Idempotent: safe to call repeatedly from a poll on the settings page.
 * Each call does at most one step (create cluster / wait / create index /
 * record done) since cluster creation itself takes real minutes and a
 * Worker invocation cannot block that long.
 */
export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) {
    return new Response(JSON.stringify({ error: "not signed in" }), { status: 401, headers: { "content-type": "application/json" } });
  }

  try {
    const status = await advanceAtlasProvisioning(env, user.id);
    return new Response(JSON.stringify(status), { headers: { "content-type": "application/json" } });
  } catch (error) {
    return new Response(
      JSON.stringify({ status: "creating", detail: error instanceof Error ? error.message : String(error) }),
      { status: 502, headers: { "content-type": "application/json" } },
    );
  }
};
