import * as client from "openid-client";
import { NextRequest, NextResponse } from "next/server";
import { oidc } from "@/lib/oidc";
import { cookieOptions, seal, Session, SESSION_COOKIE, SESSION_MAX_AGE, unseal } from "@/lib/session";

/**
 * Every page needs a session. Access tokens live 15 minutes, so the proxy refreshes them here —
 * before rendering, the only place a page request can still set a cookie.
 */
export async function proxy(request: NextRequest) {
  const session = await unseal<Session>(request.cookies.get(SESSION_COOKIE)?.value);
  const login = new URL(`/auth/login?returnTo=${encodeURIComponent(request.nextUrl.pathname)}`, request.url);
  if (!session) return NextResponse.redirect(login);
  if (session.expiresAt - 60 > Date.now() / 1000) return NextResponse.next();
  if (!session.refreshToken) return NextResponse.redirect(login);

  let fresh: string;
  try {
    const tokens = await client.refreshTokenGrant(await oidc(), session.refreshToken);
    fresh = await seal(
      {
        ...session,
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token ?? session.refreshToken,
        expiresAt: Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 900),
      },
      SESSION_MAX_AGE,
    );
  } catch {
    const response = NextResponse.redirect(login);
    response.cookies.delete(SESSION_COOKIE);
    return response;
  }
  // Hand the new cookie to this render too, not only to the browser.
  request.cookies.set(SESSION_COOKIE, fresh);
  const response = NextResponse.next({ request: { headers: request.headers } });
  response.cookies.set(SESSION_COOKIE, fresh, cookieOptions(SESSION_MAX_AGE));
  return response;
}

export const config = {
  matcher: ["/((?!auth/|signed-out|_next/|favicon.ico).*)"],
};
