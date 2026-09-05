import type { Env } from "../../lib/env";
import { getSessionUser } from "../../lib/session";

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const user = await getSessionUser(env, request);
  if (!user) return new Response(JSON.stringify({ signedIn: false }), { status: 200, headers: { "content-type": "application/json" } });
  return new Response(JSON.stringify({ signedIn: true, user }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
