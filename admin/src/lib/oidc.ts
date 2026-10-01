import "server-only";
import * as client from "openid-client";
import { config } from "./config";

let cached: Promise<client.Configuration> | null = null;

/** Discovery result, cached per server instance. */
export function oidc(): Promise<client.Configuration> {
  cached ??= client
    .discovery(
      new URL(config.issuer),
      config.clientId,
      undefined,
      client.ClientSecretBasic(config.clientSecret),
      config.issuer.startsWith("http://") ? { execute: [client.allowInsecureRequests] } : undefined,
    )
    .catch((err) => {
      cached = null;
      throw err;
    });
  return cached;
}

export const SCOPE = "openid email profile pact offline_access";

export function redirectUri(): string {
  return `${config.appUrl}/auth/callback`;
}
