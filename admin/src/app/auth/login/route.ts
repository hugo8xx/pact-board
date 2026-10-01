import * as client from "openid-client";
import { NextRequest, NextResponse } from "next/server";
import { config } from "@/lib/config";
import { oidc, redirectUri, SCOPE } from "@/lib/oidc";
import { cookieOptions, LOGIN_COOKIE, seal } from "@/lib/session";

/** Start sign-in at the authorization server: PKCE, state and nonce, for the Admin API audience. */
export async function GET(request: NextRequest) {
  const returnTo = safeReturn(request.nextUrl.searchParams.get("returnTo"));
  const verifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const url = client.buildAuthorizationUrl(await oidc(), {
    redirect_uri: redirectUri(),
    scope: SCOPE,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: "S256",
    state,
    nonce,
    resource: config.adminAudience,
  });
  const response = NextResponse.redirect(url);
  response.cookies.set(LOGIN_COOKIE, await seal({ state, verifier, nonce, returnTo }, 600), cookieOptions(600));
  return response;
}

/** Only same-site paths, so the login link can't be used to bounce people elsewhere. */
function safeReturn(value: string | null): string {
  return value && value.startsWith("/") && !value.startsWith("//") ? value : "/";
}
