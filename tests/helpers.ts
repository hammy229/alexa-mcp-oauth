import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import type { AddressInfo } from "node:net";
import { alexaMcpAuth, pinLogin, s256, type AlexaMcpAuthOptions } from "../src/index.js";

export const SECRET = "s".repeat(32);
export const REDIRECT = "https://pitangui.amazon.com/api/skill/link/TEST";
export const ALEXA = { id: "alexa", secret: "alexa-client-secret", redirectUris: [REDIRECT] };
export const SERVICE = { id: "service", secret: "service-secret", redirectUris: [], grants: ["client_credentials" as const] };
export const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
export const CHALLENGE = s256(VERIFIER);

/** An Express app with the auth router and a tiny MCP server behind requireBearer. */
export async function startServer(overrides: Partial<AlexaMcpAuthOptions> = {}) {
  const auth = alexaMcpAuth({
    secret: SECRET,
    clients: [ALEXA, SERVICE],
    login: pinLogin({ secret: "p".repeat(32), appName: "Test" }),
    ...overrides,
  });
  const app = express();
  app.use(express.json());
  app.use(auth.router);
  app.post("/mcp", auth.requireBearer, async (req, res) => {
    const server = new McpServer({ name: "test", version: "0.0.0" });
    server.registerTool("whoami", { description: "The linked user" }, async () => ({
      content: [{ type: "text", text: String(res.locals.auth.sub) }],
    }));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => void transport.close());
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });
  const http = app.listen(0);
  await new Promise((r) => http.once("listening", r));
  const base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
  return { base, close: () => new Promise((r) => http.close(r)) };
}

export const authorizeParams = (over: Record<string, string> = {}) =>
  new URLSearchParams({
    client_id: ALEXA.id,
    redirect_uri: REDIRECT,
    response_type: "code",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    state: "st8",
    name: "Sam",
    pin: "123456",
    ...over,
  });

export async function getCode(base: string, over: Record<string, string> = {}): Promise<string> {
  const res = await fetch(`${base}/authorize`, { method: "POST", body: authorizeParams(over), redirect: "manual" });
  if (res.status !== 302) throw new Error(`authorize returned ${res.status}`);
  const loc = new URL(res.headers.get("location")!);
  if (loc.searchParams.get("state") !== "st8") throw new Error("state not echoed");
  return loc.searchParams.get("code")!;
}

export const token = (base: string, params: Record<string, string>, client: { id: string; secret: string } = ALEXA) =>
  fetch(`${base}/token`, {
    method: "POST",
    body: new URLSearchParams({ client_id: client.id, client_secret: client.secret, ...params }),
  });

export async function tokensFor(base: string, name = "Sam", pin = "123456") {
  const code = await getCode(base, { name, pin });
  const res = await token(base, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER });
  return (await res.json()) as { access_token: string; refresh_token: string; expires_in: number; token_type: string };
}
