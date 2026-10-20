# Security

Please report security problems privately through GitHub: **Security → Report a vulnerability** on this repository (https://github.com/hammy229/alexa-mcp-oauth/security/advisories/new). Do not open a public issue. I will reply as soon as I can.

## Using it safely

- Generate `secret` with `openssl rand -hex 32` and keep it, and every client secret, out of source control.
- Set `issuer` to your public https origin in production instead of trusting `Host` / `X-Forwarded-*` headers.
- `pinLogin` is for demos and personal servers; use your own `LoginHandler` for real accounts.
- Tokens are stateless and cannot be revoked before they expire; see "Limits of a stateless server" in the README.
