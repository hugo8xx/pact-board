import "server-only";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value.replace(/\/$/, "");
}

/** Read lazily so `next build` works without the runtime secrets. */
export const config = {
  get issuer() {
    return required("PACT_AUTH_ISSUER");
  },
  get clientId() {
    return required("PACT_ADMIN_CLIENT_ID");
  },
  get clientSecret() {
    return required("PACT_ADMIN_CLIENT_SECRET");
  },
  /** The board's public URL; the Admin API lives under /admin/api. */
  get boardUrl() {
    return required("PACT_BOARD_URL");
  },
  /** This app's public URL, used for the OAuth redirect. */
  get appUrl() {
    const explicit = process.env.PACT_ADMIN_URL;
    if (explicit) return explicit.replace(/\/$/, "");
    const vercel = process.env.VERCEL_PROJECT_PRODUCTION_URL;
    if (vercel) return `https://${vercel}`;
    return "http://localhost:3000";
  },
  get sessionSecret() {
    const secret = required("PACT_ADMIN_SESSION_SECRET");
    if (secret.length < 32) throw new Error("PACT_ADMIN_SESSION_SECRET must be at least 32 characters");
    return secret;
  },
  /** Tokens are requested for this audience; the board refuses them anywhere but the Admin API. */
  get adminAudience() {
    return `${this.boardUrl}/admin`;
  },
};
