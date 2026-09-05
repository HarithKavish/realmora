import type { Env } from "../../lib/env";
import { destroySession } from "../../lib/session";

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const cookie = await destroySession(env, request);
  return new Response(null, { status: 204, headers: [["Set-Cookie", cookie]] });
};
