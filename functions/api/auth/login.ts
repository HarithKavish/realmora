import type { Env } from "../../lib/env";
import { AUTHORIZE_URL, OAUTH_CLIENT_ID } from "../../lib/ecosystem";
import { codeChallengeFor, generateCodeVerifier } from "../../lib/pkce";
import { randomToken } from "../../lib/crypto";

/**
 * Starts the "Sign in with HarithKavish" round trip.
 *
 * The verifier and state live in short-lived, httpOnly cookies scoped to the
 * callback path only -- nothing but that one request needs them, and they
 * are worthless once it completes.
 */
export const onRequestGet: PagesFunction<Env> = async ({ request }) => {
  const url = new URL(request.url);
  const redirectUri = `${url.origin}/api/auth/callback`;

  const verifier = generateCodeVerifier();
  const challenge = await codeChallengeFor(verifier);
  const state = randomToken(16);
  // A silent probe: "is this visitor already signed in anywhere in the
  // ecosystem?" via a real top-level navigation (required -- the shared
  // session cookie is SameSite=Lax, only ever sent on a genuine top-level
  // navigation, never a background fetch or an iframe). See callback.ts for
  // the quiet return path.
  const silent = url.searchParams.get("silent") === "1";

  const authorize = new URL(AUTHORIZE_URL);
  authorize.searchParams.set("client_id", OAUTH_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("state", state);
  if (silent) authorize.searchParams.set("prompt", "none");

  const cookieBase = "Path=/api/auth/callback; HttpOnly; Secure; SameSite=Lax; Max-Age=300";
  return new Response(null, {
    status: 302,
    headers: [
      ["Location", authorize.toString()],
      ["Set-Cookie", `rm_oauth_verifier=${verifier}; ${cookieBase}`],
      ["Set-Cookie", `rm_oauth_state=${state}; ${cookieBase}`],
    ],
  });
};
