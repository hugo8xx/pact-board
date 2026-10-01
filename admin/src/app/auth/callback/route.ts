import * as client from "openid-client";
import { NextRequest, NextResponse } from "next/server";
import { config } from "@/lib/config";
import { oidc } from "@/lib/oidc";
import { cookieOptions, LOGIN_COOKIE, LoginState, seal, SESSION_COOKIE, SESSION_MAX_AGE, unseal } from "@/lib/session";

export async function GET(request: NextRequest) {
  const login = await unseal<LoginState>(request.cookies.get(LOGIN_COOKIE)?.value);
  if (!login) return NextResponse.redirect(new URL("/auth/login", config.appUrl));
  // Rebuild the URL on the public origin: behind Vercel's proxy request.url may differ.
  const current = new URL(`/auth/callback${request.nextUrl.search}`, config.appUrl);
  let tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers;
  try {
    tokens = await client.authorizationCodeGrant(await oidc(), current, {
      pkceCodeVerifier: login.verifier,
      expectedState: login.state,
      expectedNonce: login.nonce,
      idTokenExpected: true,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "sign-in failed";
    return NextResponse.redirect(new URL(`/signed-out?error=${encodeURIComponent(message)}`, config.appUrl));
  }
  const claims = tokens.claims();
  const session = await seal(
    {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 900),
      user: { sub: String(claims?.sub), email: claims?.email as string | undefined, name: claims?.name as string | undefined },
    },
    SESSION_MAX_AGE,
  );
  const response = NextResponse.redirect(new URL(login.returnTo, config.appUrl));
  response.cookies.set(SESSION_COOKIE, session, cookieOptions(SESSION_MAX_AGE));
  response.cookies.delete(LOGIN_COOKIE);
  return response;
}
