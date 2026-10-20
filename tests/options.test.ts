import { describe, expect, it } from "vitest";
import { alexaMcpAuth, pinLogin, type LoginHandler } from "../src/index.js";
import { ALEXA, getCode, REDIRECT, SECRET, startServer, token, VERIFIER } from "./helpers.js";

const login = pinLogin({ secret: "p".repeat(32) });

describe("configuration checks", () => {
  it("requires a 32+ character secret", () => {
    expect(() => alexaMcpAuth({ secret: "short", clients: [ALEXA], login })).toThrow(/32 characters/);
  });

  it("requires a client with an id and secret", () => {
    expect(() => alexaMcpAuth({ secret: SECRET, clients: [], login })).toThrow(/at least one client/);
    expect(() => alexaMcpAuth({ secret: SECRET, clients: [{ id: "a", secret: "", redirectUris: [] }], login })).toThrow(/id and a secret/);
  });

  it("requires https redirect URIs except on localhost", () => {
    expect(() => alexaMcpAuth({ secret: SECRET, clients: [{ ...ALEXA, redirectUris: ["http://evil.example/cb"] }], login })).toThrow(/https/);
    expect(() => alexaMcpAuth({ secret: SECRET, clients: [{ ...ALEXA, redirectUris: ["http://localhost:8080/cb"] }], login })).not.toThrow();
  });
});

describe("issuer and resource path", () => {
  it("uses the configured issuer and resource path in metadata and token audience", async () => {
    const s = await startServer({ issuer: "https://mcp.example.com/", resourcePath: "/api/mcp" });
    const meta = (await (await fetch(`${s.base}/.well-known/oauth-protected-resource/api/mcp`)).json()) as { resource: string };
    expect(meta.resource).toBe("https://mcp.example.com/api/mcp");
    const as = (await (await fetch(`${s.base}/.well-known/oauth-authorization-server`)).json()) as { issuer: string };
    expect(as.issuer).toBe("https://mcp.example.com");
    await s.close();
  });
});

describe("custom login handlers", () => {
  it("uses your own user lookup and passes through only the login fields", async () => {
    const seen: Record<string, string>[] = [];
    const users: Record<string, string> = { "sam@example.com": "correct horse" };
    const custom: LoginHandler = {
      render: ({ action, hidden, error }) => `<form method="post" action="${action}">${hidden}<input name="email"><input name="password">${error ?? ""}</form>`,
      async authenticate(form) {
        seen.push(form);
        return users[form.email ?? ""] === form.password ? { sub: `user:${form.email}` } : { error: "Wrong email or password." };
      },
    };
    const s = await startServer({ login: custom });
    const bad = await fetch(`${s.base}/authorize`, {
      method: "POST",
      body: new URLSearchParams({ client_id: ALEXA.id, redirect_uri: REDIRECT, response_type: "code", code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", code_challenge_method: "S256", email: "sam@example.com", password: "nope" }),
      redirect: "manual",
    });
    expect(await bad.text()).toContain("Wrong email or password.");
    expect(seen[0]).toEqual({ email: "sam@example.com", password: "nope" });

    const code = await getCode(s.base, { email: "sam@example.com", password: "correct horse" });
    const res = await token(s.base, { grant_type: "authorization_code", code, redirect_uri: REDIRECT, code_verifier: VERIFIER });
    expect(res.status).toBe(200);
    await s.close();
  });
});

describe("pinLogin", () => {
  it("escapes the app name in the page", () => {
    const html = pinLogin({ secret: "p".repeat(32), appName: "<script>x</script>" }).render({ action: "/authorize", hidden: "", clientId: "c" });
    expect(html).not.toContain("<script>x</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("honours a custom minimum PIN length", async () => {
    const l = pinLogin({ secret: "p".repeat(32), minPinLength: 8 });
    expect(await l.authenticate({ name: "a", pin: "1234567" })).toHaveProperty("error");
    expect(await l.authenticate({ name: "a", pin: "12345678" })).toHaveProperty("sub");
  });
});
