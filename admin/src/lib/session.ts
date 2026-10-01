import "server-only";
import { EncryptJWT, jwtDecrypt } from "jose";
import { config } from "./config";

export const SESSION_COOKIE = "pact_admin";
export const LOGIN_COOKIE = "pact_admin_login";
export const SESSION_MAX_AGE = 12 * 60 * 60;

export type Session = {
  accessToken: string;
  refreshToken?: string;
  /** Epoch seconds when the access token expires. */
  expiresAt: number;
  user: { sub: string; email?: string; name?: string };
};

export type LoginState = { state: string; verifier: string; nonce: string; returnTo: string };

async function key(): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(config.sessionSecret));
  return new Uint8Array(digest);
}

/** Cookies carry tokens, so they are encrypted (A256GCM), not just signed. */
export async function seal(payload: Session | LoginState, maxAgeSeconds: number): Promise<string> {
  return new EncryptJWT({ ...payload })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(`${maxAgeSeconds}s`)
    .encrypt(await key());
}

export async function unseal<T>(token: string | undefined): Promise<T | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtDecrypt(token, await key());
    return payload as unknown as T;
  } catch {
    return null;
  }
}

export const cookieOptions = (maxAge: number) => ({
  httpOnly: true,
  secure: config.appUrl.startsWith("https://"),
  sameSite: "lax" as const,
  path: "/",
  maxAge,
});
