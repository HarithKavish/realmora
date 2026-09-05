/**
 * account.harithkavish.com's OAuth 2.0 authorization server -- the front
 * door session originates at AUTH_HOST (auth.harithkavish.com), so that is
 * where a not-yet-authenticated visitor gets a real login page and, once
 * signed in, a code back for this client. See account-repo lib/oauth/*.
 */
const AUTH_HOST = "auth.harithkavish.com";

export const AUTHORIZE_URL = `https://${AUTH_HOST}/oauth/authorize`;
export const TOKEN_URL = `https://${AUTH_HOST}/api/oauth/token`;
export const USERINFO_URL = `https://${AUTH_HOST}/api/oauth/userinfo`;

export const OAUTH_CLIENT_ID = "realmora";

export interface EcosystemProfile {
  sub: string;
  name: string;
  preferred_username: string | null;
  picture: string | null;
}

export async function exchangeCodeForToken(params: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientSecret: string;
}): Promise<{ accessToken: string } | null> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: OAUTH_CLIENT_ID,
    client_secret: params.clientSecret,
    code: params.code,
    code_verifier: params.codeVerifier,
    redirect_uri: params.redirectUri,
  });

  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) return null;

  const data = (await response.json()) as { access_token?: string };
  if (!data.access_token) return null;
  return { accessToken: data.access_token };
}

export async function fetchProfile(accessToken: string): Promise<EcosystemProfile | null> {
  const response = await fetch(USERINFO_URL, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) return null;
  return (await response.json()) as EcosystemProfile;
}
