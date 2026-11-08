# alexa-mcp-oauth

**Drop-in OAuth 2.1 for self-hosted MCP servers that link to Alexa+: one Express router and one middleware, stateless, with a test for every item on Amazon's checklist.**

[![CI](https://github.com/hammy229/alexa-mcp-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/hammy229/alexa-mcp-oauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

## Results

| Claim | Measured | How it is checked |
|---|---|---|
| Every Alexa+ auth requirement is met | 7 of 7 checklist items, one `describe` block each | [`tests/alexa-checklist.test.ts`](tests/alexa-checklist.test.ts) |
| It is tested beyond the checklist | 39 tests across 3 files: checklist, options, and token signing | `npm test` (Vitest) |
| It works on the Node versions people run | Type check, tests, and build pass on Node 20 and 22 | GitHub Actions matrix on every push |
| It is small enough to read | About 400 lines of TypeScript in `src/`, no database | `wc -l src/*.ts` |
| It works in a real product | Account linking for [Caddie Coach](https://github.com/hammy229/caddie-coach), a submitted Alexa+ hackathon project | Extracted from that codebase |

### Alexa+ checklist coverage

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

## Why it matters

The Alexa+ MCP add-on docs list what your server's auth must do (a bare 401, RFC 9728 resource metadata, server metadata with `S256` PKCE, tokens of at most an hour) but ship no server that does it. Account linking was the step with the least guidance when building Caddie Coach, so it became its own package. It is stateless, so it runs unchanged on Lambda, Cloud Run, or a laptop behind a tunnel.

## How it works

1. **Metadata.** The router serves `/.well-known/oauth-protected-resource` (RFC 9728) and `/.well-known/oauth-authorization-server` (RFC 8414), advertising `S256` as the only PKCE method.
2. **Sign-in.** `/authorize` renders your login page through a `LoginHandler` and issues a short-lived authorization code.
3. **Tokens.** `/token` checks the PKCE verifier, client, and redirect URI, then returns an access token of at most an hour and a refresh token. Opted-in clients can use `client_credentials` instead.
4. **Protection.** `requireBearer` checks the token on your MCP endpoint and puts the linked user on `res.locals.auth`.

| Choice | Why |
|---|---|
| Codes and tokens are HMAC-signed, nothing is stored | No database to run, so it deploys anywhere |
| Tokens carry your resource URI as the audience (RFC 8707) | A token for your server is useless anywhere else |
| No dynamic client registration | Alexa+ does not use it, and configured clients are easier to reason about |
| Access token lifetime capped at 3600 even if configured higher | Alexa+ requires it, so misconfiguration cannot break certification |

### Signing users in

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

### Options

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

### Setting up the Alexa+ add-on

1. Deploy your MCP server with this package, or run it locally behind a tunnel (`cloudflared tunnel --url http://localhost:3000`), which the Alexa+ quickstart allows during development.
2. `alexa-ai new mcp --name "My Add-on" --locale en-US --mcp-server-url "https://<your-host>/mcp"`.
3. In account linking, use authorization URI `https://<your-host>/authorize`, token URI `https://<your-host>/token`, and the client id and secret you configured. Copy the redirect URIs Alexa+ shows into your client's `redirectUris`.
4. `alexa-ai deploy`, then link the account from the Alexa app.

## Tech stack

TypeScript, Node 20+, Express 4 and 5, Vitest, GitHub Actions.

## Getting started

```bash
npm install github:hammy229/alexa-mcp-oauth
```

Then mount the router and middleware as in the example at the top, or run the complete server:

```bash
git clone https://github.com/hammy229/alexa-mcp-oauth && cd alexa-mcp-oauth
npm install
npm run example
```

## Project structure

```
src/index.ts      public API: alexaMcpAuth, pinLogin, escapeHtml, and the types
src/router.ts     metadata, /authorize, /token, requireBearer and verifyAccessToken
src/tokens.ts     HMAC signing and checking of codes and tokens
src/login.ts      pinLogin and the LoginHandler interface
examples/         a complete MCP server using the package
tests/            checklist, options, and token tests
```

## Testing

```bash
npm test         # checklist, options and token tests
npm run lint     # type check
npm run build
```

CI runs the type check, tests, and the build on Node 20 and 22 on every push.

## Limitations and next steps

- **No revocation.** A token stays valid until it expires (an hour for access tokens). Unlinking takes effect when the refresh token expires, or immediately if you rotate `secret` (which signs everyone out).
- **Refresh tokens are not single-use.** Refreshing returns a new pair, but the old refresh token also keeps working until it expires. If you need rotation with reuse detection, keep a denylist of used refresh tokens in your own store.
- **Authorization codes can be replayed for their 5 minutes**, though only by the same client, with the same redirect URI and the PKCE verifier, which the client never sends anywhere else.

These are the usual trade-offs of signed tokens. For a production identity service with sessions and revocation, put a managed provider (Amazon Cognito, Auth0 and so on) behind the same endpoints.

## License

MIT, see [LICENSE](LICENSE). Built by [Arham Doshi](https://arhamdoshi.dev). Security reports: see [SECURITY.md](SECURITY.md).
