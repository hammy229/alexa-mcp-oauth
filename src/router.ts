import express, { type Request, type RequestHandler, type Response, type Router } from "express";
import { escapeHtml, page, type LoginHandler } from "./login.js";
import { s256, safeEqual, signToken, verifyToken, type TokenClaims } from "./tokens.js";

export type GrantType = "authorization_code" | "refresh_token" | "client_credentials";

export interface OAuthClient {
  id: string;
  secret: string;
  /** Exact redirect URIs this client may use (Alexa+ shows them in the add-on's account-linking settings). */
  redirectUris: string[];
  /** Defaults to authorization_code + refresh_token. Add client_credentials for service-level access. */
  grants?: GrantType[];
}

export interface AlexaMcpAuthOptions {
  /** Signs every code and token. 32+ random characters; changing it invalidates everything issued. */
  secret: string;
  clients: OAuthClient[];
  /** The sign-in step on /authorize. Use `pinLogin()` or your own. */
  login: LoginHandler;
  /** Public https origin, for example `https://mcp.example.com`. Derived from each request when unset. */
  issuer?: string;
  /** Path of the protected MCP endpoint. Default `/mcp`. */
  resourcePath?: string;
  /** Access-token lifetime in seconds. Default 3600, the most Alexa+ allows. */
  accessTokenTtl?: number;
  /** Refresh-token lifetime in seconds. Default 30 days. */
  refreshTokenTtl?: number;
  /**
   * Send `WWW-Authenticate: Bearer resource_metadata=...` with 401s, as the MCP authorization spec
   * describes. Default false: the Alexa+ checklist asks for a 401 without the header.
   */
  wwwAuthenticate?: boolean;
}

export interface AuthInfo {
  /** The linked user (or `client:<id>` for client credentials). */
  sub: string;
  clientId: string;
  expiresAt: number;
}

export interface AlexaMcpAuth {
  /** Mount at the app root: metadata, /authorize and /token. */
  router: Router;
  /** Protects a route. Sets `res.locals.auth` (AuthInfo) on success; bare 401 otherwise. */
  requireBearer: RequestHandler;
  /** Verifies an access token for a request; for custom transports. */
  verifyAccessToken(token: string, req: Request): AuthInfo | undefined;
}

const DEFAULT_GRANTS: GrantType[] = ["authorization_code", "refresh_token"];
const CODE_TTL = 300;
const MAX_ACCESS_TTL = 3600;
const PARAMS = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method", "state", "resource", "scope"] as const;
type AuthorizeParams = Record<(typeof PARAMS)[number], string>;

const str = (v: unknown) => (typeof v === "string" ? v : "");

export function alexaMcpAuth(opts: AlexaMcpAuthOptions): AlexaMcpAuth {
  if (opts.secret.length < 32) throw new Error("alexa-mcp-oauth: secret must be at least 32 characters");
  if (!opts.clients.length) throw new Error("alexa-mcp-oauth: at least one client is required");
  for (const c of opts.clients) {
    if (!c.id || !c.secret) throw new Error("alexa-mcp-oauth: every client needs an id and a secret");
    for (const uri of c.redirectUris) {
      const u = new URL(uri);
      if (u.protocol !== "https:" && u.hostname !== "localhost" && u.hostname !== "127.0.0.1") {
        throw new Error(`alexa-mcp-oauth: redirect URI must be https: ${uri}`);
      }
    }
  }

  const resourcePath = opts.resourcePath ?? "/mcp";
  const accessTtl = Math.min(opts.accessTokenTtl ?? MAX_ACCESS_TTL, MAX_ACCESS_TTL);
  const refreshTtl = opts.refreshTokenTtl ?? 30 * 24 * 3600;
  const clients = new Map(opts.clients.map((c) => [c.id, c]));
  const grantsOf = (c: OAuthClient) => c.grants ?? DEFAULT_GRANTS;

  const issuer = (req: Request) => {
    if (opts.issuer) return opts.issuer.replace(/\/$/, "");
    const proto = str(req.header("x-forwarded-proto")).split(",")[0] || req.protocol;
    return `${proto}://${req.header("x-forwarded-host") ?? req.get("host")}`;
  };
  const resource = (req: Request) => `${issuer(req)}${resourcePath}`;

  const issue = (req: Request, client: OAuthClient, sub: string, withRefresh: boolean) => {
    const base = { sub, cid: client.id, aud: resource(req) };
    return {
      access_token: signToken(opts.secret, { typ: "access", ...base }, accessTtl),
      token_type: "Bearer",
      expires_in: accessTtl,
      ...(withRefresh ? { refresh_token: signToken(opts.secret, { typ: "refresh", ...base }, refreshTtl) } : {}),
    };
  };

  const verifyAccessToken = (token: string, req: Request): AuthInfo | undefined => {
    const c = verifyToken(opts.secret, token, "access");
    if (!c || !clients.has(c.cid) || c.aud !== resource(req)) return undefined;
    return { sub: c.sub, clientId: c.cid, expiresAt: c.exp };
  };

  const requireBearer: RequestHandler = (req, res, next) => {
    const m = /^Bearer\s+(\S+)$/i.exec(req.header("authorization") ?? "");
    const auth = m ? verifyAccessToken(m[1]!, req) : undefined;
    if (!auth) {
      if (opts.wwwAuthenticate) {
        res.set("WWW-Authenticate", `Bearer resource_metadata="${issuer(req)}/.well-known/oauth-protected-resource${resourcePath}"`);
      }
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    res.locals.auth = auth;
    next();
  };

  // ---- authorization endpoint ----

  const readParams = (src: Record<string, unknown>) =>
    Object.fromEntries(PARAMS.map((k) => [k, str(src[k])])) as AuthorizeParams;

  /** Problems with the client or redirect URI are shown, never redirected (RFC 6749 §4.1.2.1). */
  const clientProblem = (p: AuthorizeParams): string | undefined => {
    const client = clients.get(p.client_id);
    if (!client || !grantsOf(client).includes("authorization_code")) return "Unknown client.";
    if (!client.redirectUris.includes(p.redirect_uri)) return "This redirect URI is not registered for the client.";
    return undefined;
  };

  /** Problems that are safe to report back to the client's redirect URI. */
  const requestProblem = (p: AuthorizeParams, req: Request): string | undefined => {
    if (p.response_type !== "code") return "unsupported_response_type";
    if (p.code_challenge_method !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(p.code_challenge)) return "invalid_request";
    if (p.resource && p.resource !== resource(req)) return "invalid_target";
    return undefined;
  };

  const redirect = (res: Response, uri: string, params: Record<string, string>) => {
    const u = new URL(uri);
    for (const [k, v] of Object.entries(params)) if (v) u.searchParams.set(k, v);
    res.redirect(302, u.toString());
  };

  const hidden = (p: AuthorizeParams) =>
    PARAMS.filter((k) => p[k]).map((k) => `<input type="hidden" name="${k}" value="${escapeHtml(p[k])}">`).join("");

  const showError = (res: Response, message: string) =>
    res.status(400).type("html").send(page("Cannot link", `<h1>Cannot link</h1><p>${escapeHtml(message)}</p>`));

  const form = express.urlencoded({ extended: false, limit: "16kb" });
  const router = express.Router();

  router.get("/authorize", (req, res) => {
    const p = readParams(req.query as Record<string, unknown>);
    const bad = clientProblem(p);
    if (bad) return void showError(res, bad);
    const err = requestProblem(p, req);
    if (err) return void redirect(res, p.redirect_uri, { error: err, state: p.state });
    res.set("Cache-Control", "no-store").type("html").send(opts.login.render({ action: "/authorize", hidden: hidden(p), clientId: p.client_id }));
  });

  router.post("/authorize", form, async (req, res, next) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const p = readParams(body);
      const bad = clientProblem(p);
      if (bad) return void showError(res, bad);
      const err = requestProblem(p, req);
      if (err) return void redirect(res, p.redirect_uri, { error: err, state: p.state });
      const fields = Object.fromEntries(Object.entries(body).filter(([k]) => !(PARAMS as readonly string[]).includes(k)).map(([k, v]) => [k, str(v)]));
      const result = await opts.login.authenticate(fields);
      if ("error" in result) {
        res.status(400).set("Cache-Control", "no-store").type("html")
          .send(opts.login.render({ action: "/authorize", hidden: hidden(p), clientId: p.client_id, error: result.error }));
        return;
      }
      const code = signToken(
        opts.secret,
        { typ: "code", sub: result.sub, cid: p.client_id, aud: resource(req), cc: p.code_challenge, ru: p.redirect_uri },
        CODE_TTL,
      );
      redirect(res, p.redirect_uri, { code, state: p.state });
    } catch (e) {
      next(e);
    }
  });

  // ---- token endpoint ----

  const tokenError = (res: Response, status: number, error: string, description?: string) =>
    void res.status(status).set({ "Cache-Control": "no-store", Pragma: "no-cache" }).json({ error, ...(description ? { error_description: description } : {}) });

  const authenticateClient = (req: Request): OAuthClient | undefined => {
    let id = str(req.body?.client_id);
    let secret = str(req.body?.client_secret);
    const basic = /^Basic\s+(\S+)$/i.exec(req.header("authorization") ?? "");
    if (basic) {
      const [rawId = "", ...rest] = Buffer.from(basic[1]!, "base64").toString("utf8").split(":");
      id = decodeURIComponent(rawId);
      secret = decodeURIComponent(rest.join(":"));
    }
    const client = clients.get(id);
    return client && safeEqual(secret, client.secret) ? client : undefined;
  };

  const sameClient = (claims: TokenClaims, client: OAuthClient) => claims.cid === client.id;

  router.post("/token", form, (req, res) => {
    const client = authenticateClient(req);
    if (!client) return tokenError(res, 401, "invalid_client");
    const grant = str(req.body?.grant_type) as GrantType;
    if (!grantsOf(client).includes(grant)) return tokenError(res, 400, "unauthorized_client");
    const requested = str(req.body?.resource);
    if (requested && requested !== resource(req)) return tokenError(res, 400, "invalid_target");
    const ok = (body: object) => void res.set({ "Cache-Control": "no-store", Pragma: "no-cache" }).json(body);

    if (grant === "authorization_code") {
      const code = verifyToken(opts.secret, str(req.body?.code), "code");
      if (!code || !sameClient(code, client) || code.ru !== str(req.body?.redirect_uri) || code.aud !== resource(req)) {
        return tokenError(res, 400, "invalid_grant");
      }
      const verifier = str(req.body?.code_verifier);
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || !code.cc || !safeEqual(s256(verifier), code.cc)) {
        return tokenError(res, 400, "invalid_grant", "PKCE verification failed");
      }
      return ok(issue(req, client, code.sub, grantsOf(client).includes("refresh_token")));
    }

    if (grant === "refresh_token") {
      const refresh = verifyToken(opts.secret, str(req.body?.refresh_token), "refresh");
      if (!refresh || !sameClient(refresh, client) || refresh.aud !== resource(req)) return tokenError(res, 400, "invalid_grant");
      return ok(issue(req, client, refresh.sub, true));
    }

    if (grant === "client_credentials") {
      // Service-level access: no user, no refresh token, at most an hour.
      return ok(issue(req, client, `client:${client.id}`, false));
    }

    return tokenError(res, 400, "unsupported_grant_type");
  });

  // ---- discovery ----

  const protectedResource: RequestHandler = (req, res) => {
    res.json({ resource: resource(req), authorization_servers: [issuer(req)], bearer_methods_supported: ["header"] });
  };
  router.get("/.well-known/oauth-protected-resource", protectedResource);
  router.get(`/.well-known/oauth-protected-resource${resourcePath}`, protectedResource);

  router.get("/.well-known/oauth-authorization-server", (req, res) => {
    const base = issuer(req);
    const grants = [...new Set(opts.clients.flatMap(grantsOf))];
    res.json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      response_types_supported: ["code"],
      grant_types_supported: grants,
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    });
  });

  return { router, requireBearer, verifyAccessToken };
}
