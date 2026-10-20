import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ALEXA, CHALLENGE, getCode, REDIRECT, SERVICE, startServer, token, tokensFor, VERIFIER } from "./helpers.js";

// One describe per item of the Alexa+ MCP add-on authentication checklist (see README).
let base: string;
let close: () => Promise<unknown>;

beforeAll(async () => {
  ({ base, close } = await startServer());
});
afterAll(() => close());

const mcpPost = (headers: Record<string, string> = {}) =>
  fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });

describe("1. Unauthenticated requests get 401 without WWW-Authenticate", () => {
  it("returns a bare 401 with no token", async () => {
    const res = await mcpPost();
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("returns 401 for a garbage or tampered token", async () => {
    expect((await mcpPost({ Authorization: "Bearer nope" })).status).toBe(401);
    const { access_token } = await tokensFor(base);
    expect((await mcpPost({ Authorization: `Bearer ${access_token.slice(0, -3)}abc` })).status).toBe(401);
  });

  it("can send WWW-Authenticate for clients that follow the MCP authorization spec", async () => {
    const s = await startServer({ wwwAuthenticate: true });
    const res = await fetch(`${s.base}/mcp`, { method: "POST" });
    expect(res.headers.get("www-authenticate")).toBe(`Bearer resource_metadata="${s.base}/.well-known/oauth-protected-resource/mcp"`);
    await s.close();
  });
});

describe("2. Protected Resource Metadata (RFC 9728) at the well-known URI", () => {
  it("is served at the root and the path-suffixed well-known URI", async () => {
    for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
      const meta = (await (await fetch(`${base}${path}`)).json()) as Record<string, unknown>;
      expect(meta).toEqual({ resource: `${base}/mcp`, authorization_servers: [base], bearer_methods_supported: ["header"] });
    }
  });
});

describe("3. Authorization server metadata at /.well-known/oauth-authorization-server", () => {
  it("lists the endpoints and includes S256 in code_challenge_methods_supported", async () => {
    const meta = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    expect(meta.issuer).toBe(base);
    expect(meta.authorization_endpoint).toBe(`${base}/authorize`);
    expect(meta.token_endpoint).toBe(`${base}/token`);
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
    expect(meta.grant_types_supported).toEqual(["authorization_code", "refresh_token", "client_credentials"]);
  });

  it("does not advertise Dynamic Client Registration", async () => {
    const meta = (await (await fetch(`${base}/.well-known/oauth-authorization-server`)).json()) as Record<string, unknown>;
    expect(meta.registration_endpoint).toBeUndefined();
    expect((await fetch(`${base}/register`, { method: "POST" })).status).toBe(404);
  });
});

describe("4. Tier 2: authorization_code with PKCE (user-level consent)", () => {
  it("shows the sign-in page for a valid request", async () => {
    const q = new URLSearchParams({ client_id: ALEXA.id, redirect_uri: REDIRECT, response_type: "code", code_challenge: CHALLENGE, code_challenge_method: "S256", state: "st8" });
    const res = await fetch(`${base}/authorize?${q}`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Link Test");
    expect(html).toContain('name="code_challenge"');
  });

  it("issues Bearer tokens with an expires_in of at most 3600 and a refresh token", async () => {
    const t = await tokensFor(base);
    expect(t.token_type).toBe("Bearer");
    expect(t.expires_in).toBeLessThanOrEqual(3600);
    expect(t.refresh_token).toBeTruthy();
  });

  it("requires S256: rejects plain and missing challenges", async () => {
    for (const over of [{ code_challenge_method: "plain" }, { code_challenge: "" }, { code_challenge: "short" }]) {
      const res = await fetch(`${base}/authorize`, { method: "POST", body: new URLSearchParams({ client_id: ALEXA.id, redirect_uri: REDIRECT, response_type: "code", code_challenge: CHALLENGE, code_challenge_method: "S256", state: "st8", ...over }), redirect: "manual" });
      expect(new URL(res.headers.get("location")!).searchParams.get("error")).toBe("invalid_request");
    }
  });

  it("rejects a wrong PKCE verifier", async () => {
    const code = await getCode(base);
    const res = await token(base, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: "x".repeat(43) });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: "invalid_grant", error_description: "PKCE verification failed" });
  });

  it("rejects a redirect_uri that differs from the one in the authorization request", async () => {
    const code = await getCode(base);
    const res = await token(base, { grant_type: "authorization_code", code, redirect_uri: "https://evil.example/cb", code_verifier: VERIFIER });
    expect(res.status).toBe(400);
  });

  it("never redirects to an unregistered redirect URI or for an unknown client", async () => {
    for (const over of [{ redirect_uri: "https://evil.example/cb" }, { client_id: "nobody" }]) {
      const res = await fetch(`${base}/authorize`, { method: "POST", body: new URLSearchParams({ client_id: ALEXA.id, redirect_uri: REDIRECT, response_type: "code", code_challenge: CHALLENGE, code_challenge_method: "S256", ...over }), redirect: "manual" });
      expect(res.status).toBe(400);
      expect(res.headers.get("location")).toBeNull();
    }
  });

  it("re-shows the sign-in page when the login fails, without issuing a code", async () => {
    const res = await fetch(`${base}/authorize`, { method: "POST", body: new URLSearchParams({ client_id: ALEXA.id, redirect_uri: REDIRECT, response_type: "code", code_challenge: CHALLENGE, code_challenge_method: "S256", name: "Sam", pin: "1" }), redirect: "manual" });
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
    expect(await res.text()).toContain('role="alert"');
  });

  it("authenticates the client with HTTP Basic as well as form fields", async () => {
    const code = await getCode(base);
    const res = await fetch(`${base}/token`, {
      method: "POST",
      headers: { Authorization: `Basic ${Buffer.from(`${ALEXA.id}:${ALEXA.secret}`).toString("base64")}` },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("rejects a wrong client secret", async () => {
    const code = await getCode(base);
    const res = await token(base, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER }, { id: ALEXA.id, secret: "wrong" });
    expect(res.status).toBe(401);
  });

  it("refreshes, and never accepts an access token as a refresh token", async () => {
    const t = await tokensFor(base);
    const ok = await token(base, { grant_type: "refresh_token", refresh_token: t.refresh_token });
    expect(ok.status).toBe(200);
    const bad = await token(base, { grant_type: "refresh_token", refresh_token: t.access_token });
    expect(bad.status).toBe(400);
  });
});

describe("5. Tier 1: client_credentials (service-level access)", () => {
  it("issues an access token of at most 3600 seconds and no refresh token", async () => {
    const res = await token(base, { grant_type: "client_credentials" }, SERVICE);
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status).toBe(200);
    expect(body.expires_in).toBeLessThanOrEqual(3600);
    expect(body.refresh_token).toBeUndefined();
    expect((await mcpPost({ Authorization: `Bearer ${body.access_token}` })).status).toBe(200);
  });

  it("is refused for clients not allowed to use it", async () => {
    const res = await token(base, { grant_type: "client_credentials" }, ALEXA);
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("unauthorized_client");
  });

  it("caps the token lifetime at 3600 even if configured higher", async () => {
    const s = await startServer({ accessTokenTtl: 86_400 });
    const body = (await (await token(s.base, { grant_type: "client_credentials" }, SERVICE)).json()) as { expires_in: number };
    expect(body.expires_in).toBe(3600);
    await s.close();
  });
});

describe("6. Tokens are bound to this resource (RFC 8707)", () => {
  it("rejects a token presented to a different resource URI", async () => {
    const { access_token } = await tokensFor(base);
    expect((await mcpPost({ Authorization: `Bearer ${access_token}`, "x-forwarded-host": "other.example" })).status).toBe(401);
  });

  it("rejects a resource parameter that names another server", async () => {
    const res = await fetch(`${base}/authorize`, { method: "POST", body: new URLSearchParams({ client_id: ALEXA.id, redirect_uri: REDIRECT, response_type: "code", code_challenge: CHALLENGE, code_challenge_method: "S256", resource: "https://other.example/mcp" }), redirect: "manual" });
    expect(new URL(res.headers.get("location")!).searchParams.get("error")).toBe("invalid_target");
  });

  it("accepts the matching resource parameter", async () => {
    const code = await getCode(base, { resource: `${base}/mcp` });
    const res = await token(base, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER, resource: `${base}/mcp` });
    expect(res.status).toBe(200);
  });
});

describe("7. End to end with the MCP SDK client", () => {
  const connect = async (accessToken: string) => {
    const client = new Client({ name: "e2e", version: "0.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${accessToken}` } } }));
    return client;
  };
  const whoami = async (name: string, pin: string) => {
    const c = await connect((await tokensFor(base, name, pin)).access_token);
    const r = (await c.callTool({ name: "whoami", arguments: {} })) as { content: { text: string }[] };
    await c.close();
    return r.content[0]!.text;
  };

  it("calls a tool as the linked user, and the same name + PIN always maps to the same user", async () => {
    const ann = await whoami("Ann", "annpin1");
    expect(ann).toMatch(/^u_[0-9a-f]{32}$/);
    expect(await whoami("ann ", "annpin1")).toBe(ann);
    expect(await whoami("Ann", "annpin2")).not.toBe(ann);
  });
});
