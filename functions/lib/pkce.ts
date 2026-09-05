/** RFC 7636 PKCE, S256 only -- account.harithkavish.com's authorize endpoint rejects anything else. */

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateCodeVerifier(): string {
  // 32 random bytes -> 43-char base64url string, within the 43-128 char
  // range RFC 7636 requires.
  return base64url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function codeChallengeFor(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}
