import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/**
 * Stateless, HMAC-SHA256 signed tokens: `base64url(json).base64url(mac)`. Authorization codes, access
 * tokens and refresh tokens all use this format and are told apart by `typ`, so one kind can never be
 * replayed as another. Nothing is stored server side, which keeps the server free of any database and
 * lets it run on serverless platforms unchanged.
 */
export type TokenType = "code" | "access" | "refresh";

export interface TokenClaims {
  typ: TokenType;
  /** Subject: the linked user's stable id (or `client:<id>` for client credentials). */
  sub: string;
  /** Client id the token was issued to. */
  cid: string;
  /** Audience: the protected resource URI (RFC 8707) the token is bound to. */
  aud: string;
  /** Expiry, seconds since the epoch. */
  exp: number;
  /** PKCE code challenge (codes only). */
  cc?: string;
  /** Redirect URI (codes only). */
  ru?: string;
}

const b64 = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const mac = (secret: string, data: string) => createHmac("sha256", secret).update(data).digest();
export const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Constant-time string comparison. */
export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export function signToken(secret: string, claims: Omit<TokenClaims, "exp">, ttlSeconds: number): string {
  const body = b64(JSON.stringify({ ...claims, exp: nowSeconds() + ttlSeconds }));
  return `${body}.${b64(mac(secret, body))}`;
}

/** Returns the claims if the signature, type and expiry all check out; otherwise undefined. */
export function verifyToken(secret: string, token: string, typ: TokenType): TokenClaims | undefined {
  const [body, sig, extra] = token.split(".");
  if (!body || !sig || extra !== undefined || !safeEqual(sig, b64(mac(secret, body)))) return undefined;
  try {
    const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as TokenClaims;
    return claims.typ === typ && typeof claims.exp === "number" && claims.exp > nowSeconds() ? claims : undefined;
  } catch {
    return undefined;
  }
}

/** PKCE S256: base64url(sha256(verifier)). */
export const s256 = (verifier: string) => createHash("sha256").update(verifier).digest("base64url");

/** Deterministic, opaque user id from a secret and any stable input (for example name + PIN). */
export function deriveId(secret: string, prefix: string, ...parts: string[]): string {
  return `${prefix}${mac(secret, parts.join("\n")).toString("hex").slice(0, 32)}`;
}
