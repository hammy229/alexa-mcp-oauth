/**
 * A complete Alexa+-ready MCP server in one file: `npm run example`.
 *
 * Environment (all optional for a local try-out):
 *   OAUTH_SECRET          32+ random characters (openssl rand -hex 32)
 *   ALEXA_CLIENT_SECRET   the client secret you enter in the add-on's account-linking settings
 *   ALEXA_REDIRECT_URIS   comma-separated redirect URIs shown in those settings
 *   PUBLIC_URL            your public https origin, e.g. a cloudflared tunnel URL
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { z } from "zod";
import { alexaMcpAuth, pinLogin } from "../src/index.js";

const secret = process.env.OAUTH_SECRET ?? "dev-only-secret-change-me-0123456789abcdef";
const auth = alexaMcpAuth({
  secret,
  issuer: process.env.PUBLIC_URL,
  clients: [
    {
      id: "alexa",
      secret: process.env.ALEXA_CLIENT_SECRET ?? "dev-client-secret",
      redirectUris: (process.env.ALEXA_REDIRECT_URIS ?? "https://localhost/callback").split(",").map((s) => s.trim()),
    },
  ],
  login: pinLogin({ secret: `${secret}:users`, appName: "Notes" }),
});

// Per-user state keyed by the linked user's id. Use a real store in production.
const notes = new Map<string, string[]>();

const app = express();
app.use(express.json());
app.use(auth.router);

app.post("/mcp", auth.requireBearer, async (req, res) => {
  const user = res.locals.auth.sub as string;
  const server = new McpServer({ name: "notes", version: "0.1.0" });
  server.registerTool(
    "add_note",
    { description: "Save a note for the signed-in user", inputSchema: { text: z.string().min(1).max(500) } },
    async ({ text }) => {
      notes.set(user, [...(notes.get(user) ?? []), text]);
      return { content: [{ type: "text", text: `Saved. You have ${notes.get(user)!.length} notes.` }] };
    },
  );
  server.registerTool("list_notes", { description: "Read back the signed-in user's notes" }, async () => ({
    content: [{ type: "text", text: (notes.get(user) ?? []).join("\n") || "No notes yet." }],
  }));
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => void transport.close());
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`MCP endpoint:        http://localhost:${port}/mcp  (401 without a token)`);
  console.log(`Server metadata:     http://localhost:${port}/.well-known/oauth-authorization-server`);
  console.log(`Resource metadata:   http://localhost:${port}/.well-known/oauth-protected-resource`);
});
