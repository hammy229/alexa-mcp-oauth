import { deriveId } from "./tokens.js";

/** What the /authorize page shows and how it checks the person signing in. */
export interface LoginHandler {
  /**
   * Full HTML for the sign-in page. Put `hidden` (the OAuth parameters as hidden inputs) inside a
   * `<form method="post" action="{action}">`; everything else on the page is yours.
   */
  render(ctx: LoginRenderContext): string;
  /** Checks the submitted form. Return the user's stable id, or an error to re-render the page with. */
  authenticate(form: Record<string, string>): LoginResult | Promise<LoginResult>;
}

export interface LoginRenderContext {
  action: string;
  hidden: string;
  clientId: string;
  error?: string;
}

export type LoginResult = { sub: string } | { error: string };

export const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** A small, accessible page shell for login and error pages. */
export function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1418;color:#e9eef2;font:16px/1.5 system-ui,sans-serif}
main{width:min(92vw,380px);padding:28px;border:1px solid #2a343c;border-radius:16px;background:#151c22}h1{margin:0 0 6px;font-size:22px}
p{color:#a3b1bc;margin:0 0 18px}label{display:block;font-size:13px;margin:12px 0 4px;color:#a3b1bc}
input{width:100%;box-sizing:border-box;padding:11px 12px;border-radius:10px;border:1px solid #2a343c;background:#0f1418;color:inherit;font:inherit}
button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:10px;background:#5ec2f2;color:#06212e;font:inherit;font-weight:600;cursor:pointer}
input:focus-visible,button:focus-visible{outline:2px solid #5ec2f2;outline-offset:2px}.err{color:#ff9d8f;font-size:14px;margin-top:12px}</style></head>
<body><main>${body}</main></body></html>`;
}

export interface PinLoginOptions {
  /** Secret used to derive user ids. Use a different value from the token signing secret. */
  secret: string;
  /** Shown in the page heading, for example "Caddie Coach". */
  appName?: string;
  minPinLength?: number;
}

/**
 * Account linking with no user database: the person picks a name and a PIN, and the user id is an
 * HMAC of both, so the same pair always reaches the same data and the PIN is never stored. Good for
 * hackathons, demos and personal servers. For real accounts, write a LoginHandler against your users.
 */
export function pinLogin(opts: PinLoginOptions): LoginHandler {
  const min = opts.minPinLength ?? 6;
  const app = escapeHtml(opts.appName ?? "your account");
  return {
    render({ action, hidden, error }) {
      return page(
        `Link ${opts.appName ?? "account"}`,
        `<h1>Link ${app}</h1><p>Choose a name and PIN. Use the same pair whenever you link again to reach the same data.</p>
<form method="post" action="${escapeHtml(action)}">${hidden}
<label for="name">Name</label><input id="name" name="name" autocomplete="username" required maxlength="60">
<label for="pin">PIN (at least ${min} characters)</label><input id="pin" name="pin" type="password" autocomplete="current-password" required minlength="${min}" maxlength="64">
<button type="submit">Link account</button>${error ? `<div class="err" role="alert">${escapeHtml(error)}</div>` : ""}</form>`,
      );
    },
    authenticate(form) {
      const name = (form.name ?? "").trim();
      const pin = form.pin ?? "";
      if (!name || pin.length < min) return { error: `Enter a name and a PIN of at least ${min} characters.` };
      return { sub: deriveId(opts.secret, "u_", name.toLowerCase(), pin) };
    },
  };
}
