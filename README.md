# alexa-mcp-oauth

Drop-in OAuth 2.1 for self-hosted MCP servers that link to **Alexa+**.

The Alexa+ MCP add-on docs list what your server's auth must do (a bare 401, RFC 9728 resource metadata, server metadata with `S256` PKCE, tokens of at most an hour) but ship no server that does it. This package is that server: one Express router and one middleware, with a test for every checklist item. It is stateless (codes and tokens are HMAC-signed, nothing is stored), so it runs unchanged on Lambda, Cloud Run or a laptop behind a tunnel.

```ts
import express from "express";
import { alexaMcpAuth, pinLogin } from "alexa-mcp-oauth";

const auth = alexaMcpAuth({
  secret: process.env.OAUTH_SECRET!,                       // 32+ random characters
  clients: [{
    id: "alexa",
    secret: process.env.ALEXA_CLIENT_SECRET!,
    redirectUris: process.env.ALEXA_REDIRECT_URIS!.split(","),
  }],
  login: pinLogin({ secret: process.env.USER_ID_SECRET!, appName: "My Add-on" }),
});

const app = express();
app.use(express.json());
app.use(auth.router);                                      // metadata, /authorize, /token
app.post("/mcp", auth.requireBearer, (req, res) => {
  const userId = res.locals.auth.sub;                      // the linked user
  // ...your Streamable HTTP MCP handler, keyed by userId
});
```

Install from GitHub: `npm install github:hammy229/alexa-mcp-oauth`. A complete MCP server using it is in [`examples/server.ts`](examples/server.ts) (`npm run example`).

## Alexa+ checklist coverage

Each row is a `describe` block in [`tests/alexa-checklist.test.ts`](tests/alexa-checklist.test.ts).

| Alexa+ requirement | How it is met |
|---|---|
| Unauthenticated requests get **401 without `WWW-Authenticate`** | `requireBearer` returns a bare 401 (set `wwwAuthenticate: true` for clients that follow the MCP authorization spec's header) |
| **Protected Resource Metadata** (RFC 9728) at the well-known URI | `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp` |
| **Server metadata** at `/.well-known/oauth-authorization-server` with **`S256`** in `code_challenge_methods_supported` | Served; `S256` is the only method accepted |
| **Tier 2: `authorization_code` + PKCE** (user consent) | `/authorize` shows your sign-in page; `/token` checks the verifier, client and redirect URI |
| **Tier 1: `client_credentials`** (service level): `expires_in` ≤ 3600, **no refresh token** | Opt in per client with `grants: ["client_credentials"]`; lifetime is capped at 3600 even if configured higher |
| **No Dynamic Client Registration** | Clients are configured, never registered at runtime; no `registration_endpoint` |
| Tokens bound to your server (`resource`, RFC 8707) | Tokens carry the resource URI as audience and are rejected anywhere else; a mismatched `resource` parameter gets `invalid_target` |

## Signing users in

`login` decides who is linking. Two options:

- **`pinLogin`**: the person picks a name and a PIN; their user id is an HMAC of both, so the same pair always reaches the same data and nothing is stored. Right for hackathons, demos and personal servers. Not right for real accounts: anyone who knows someone's name and PIN gets their data.
- **Your own `LoginHandler`**: render any form, check it against your users, return `{ sub }` or `{ error }`.

```ts
const login: LoginHandler = {
  render: ({ action, hidden, error }) => `
    <form method="post" action="${action}">${hidden}
      <input name="email"> <input name="password" type="password">
      <button>Link</button> ${error ? escapeHtml(error) : ""}
    </form>`,
  async authenticate({ email, password }) {
    const user = await users.verify(email, password);
    return user ? { sub: user.id } : { error: "Wrong email or password." };
  },
};
```

Put `hidden` inside your form: it carries the OAuth parameters through the sign-in. Escape anything you echo back (`escapeHtml` is exported).

## Options

| Option | Default | |
|---|---|---|
| `secret` | required | Signs codes and tokens. 32+ characters. Rotating it signs everyone out. |
| `clients` | required | `{ id, secret, redirectUris, grants? }`. Redirect URIs must be `https` (localhost excepted) and match exactly. |
| `login` | required | `pinLogin({...})` or your own `LoginHandler`. |
| `issuer` | from the request | Your public origin, e.g. `https://mcp.example.com`. Set it in production; otherwise `Host` / `X-Forwarded-*` decide. |
| `resourcePath` | `/mcp` | Path of the protected MCP endpoint. |
| `accessTokenTtl` | `3600` | Seconds; never more than 3600. |
| `refreshTokenTtl` | 30 days | Seconds. |
| `wwwAuthenticate` | `false` | Add `WWW-Authenticate: Bearer resource_metadata=...` to 401s. |

`requireBearer` puts `{ sub, clientId, expiresAt }` on `res.locals.auth`. `verifyAccessToken(token, req)` does the same check for custom transports.

## Setting up the Alexa+ add-on

1. Deploy your MCP server with this package, or run it locally behind a tunnel (`cloudflared tunnel --url http://localhost:3000`), which the Alexa+ quickstart allows during development.
2. `alexa-ai new mcp --name "My Add-on" --locale en-US --mcp-server-url "https://<your-host>/mcp"`.
3. In account linking, use authorization URI `https://<your-host>/authorize`, token URI `https://<your-host>/token`, and the client id and secret you configured. Copy the redirect URIs Alexa+ shows into your client's `redirectUris`.
4. `alexa-ai deploy`, then link the account from the Alexa app.

## Limits of a stateless server

- **No revocation.** A token stays valid until it expires (an hour for access tokens). Unlinking takes effect when the refresh token expires, or immediately if you rotate `secret` (which signs everyone out).
- **Refresh tokens are not single-use.** Refreshing returns a new pair, but the old refresh token also keeps working until it expires. If you need rotation with reuse detection, keep a denylist of used refresh tokens in your own store.
- **Authorization codes can be replayed for their 5 minutes**, though only by the same client, with the same redirect URI and the PKCE verifier, which the client never sends anywhere else.

These are the usual trade-offs of signed tokens. For a production identity service with sessions and revocation, put a managed provider (Amazon Cognito, Auth0 and so on) behind the same endpoints.

## Develop

```bash
npm install
npm test         # checklist, options and token tests
npm run lint
npm run build
```

Requires Node 20+. Works with Express 4 and 5.

## Origin

Extracted from [Caddie Coach](https://github.com/hammy229/caddie-coach), an Alexa+ golf caddie built for the Amazon Developer "Build, Ship, Shape" Hackathon 2026, where account linking was the step with the least guidance.

## License

MIT
