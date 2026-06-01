# Securing the key — how to use this safely in a JS framework

This is the most important document in the package. Read it before you ship.

## The problem, stated plainly

A single-page app (React, Angular, Vue, …) is a **public client**. Everything it ships — every line of JavaScript, every constant — is downloaded to the browser and can be read by anyone who opens DevTools. **A key hard-coded into your SPA bundle is not a secret.** An attacker can extract it and produce perfectly valid signatures and ciphertext.

So putting `SecureBridge.configure({ key: 'AbC123...' })` with a literal/build-time key into a decoupled SPA gives you **integrity and anti-tampering and anti-naive-bot value, but not confidentiality or authenticity against a motivated attacker.** That may be exactly enough (see "When static is fine"), but you must choose it knowingly.

## The four sources, from weakest to strongest

| `key_source` | Where the key lives | Protects against | Use when |
|---|---|---|---|
| **`static`** | In the JS bundle (decoupled SPA) or `.env`-served constant | Tampering, replay, naive bots, log/extension exposure | Local dev, internal tools, or you only need anti-tampering on top of TLS |
| **`session`** | Laravel session, injected per-page by `@secureBridge` | Above **+ key is never in a static bundle**, rotates per session | **Same-origin Blade apps** that make AJAX/fetch calls |
| **`token`** | Issued by the server **after login**, kept in **browser memory only** | Above, for **decoupled SPAs** — no key in the bundle, different key per session, useless to anyone reading your JS | **Decoupled React/Angular/Vue apps** (recommended) |
| **BFF** (architecture) | Only on the server; browser holds an HttpOnly cookie | Above **+ no usable secret in the browser at all** | Highest-security apps; you can run a server-side proxy |

> ### The honest limit nobody should hide from you
> None of these make the browser a trusted secret store. **If your site has an XSS vulnerability, the attacker's script runs with your page's privileges** and can use the in-memory key (or the auth token, or the session cookie) for as long as the page is open. Per-session keys remove the "one static key compromises every user forever" problem and the "key sits in the bundle" problem — they do **not** make signing meaningful in the presence of XSS. The only thing that does is *not having XSS* (CSP, output encoding, dependency hygiene) plus, for the highest bar, a **BFF** so no usable secret is ever in the browser.

## Recommended for decoupled SPAs: the `token` handshake

The idea: **never ship a key. Ask the server for one after the user logs in.**

```
 1. User logs in normally (Sanctum / Passport / JWT / your auth).  -> gets auth token
 2. SPA calls POST /secure-bridge/handshake with that token.       -> server mints a
                                                                       random per-session key,
                                                                       stores it bound to the
                                                                       token, returns it once.
 3. SPA keeps the key in a JS variable (MEMORY ONLY).              -> signs all later requests
 4. Server verifies each request against the per-token key.
```

Why this is meaningfully better:
- **Nothing in the bundle.** Reading your JavaScript reveals no key.
- **Per-session.** Every login gets a different key; revoking the session/token kills it.
- **Bound to auth.** Only an authenticated user can obtain a key, and it only validates *their* requests.

### Server setup

```env
SECURE_BRIDGE_KEY_SOURCE=token
SECURE_BRIDGE_HANDSHAKE=true
SECURE_BRIDGE_HANDSHAKE_TTL=3600
CACHE_STORE=redis   # use a shared store in multi-server deployments
```

```php
// config/secure-bridge.php
'handshake' => [
    'enabled'    => true,
    'route'      => 'secure-bridge/handshake',
    'middleware' => ['auth:sanctum'],   // <-- YOUR auth guard
    'ttl'        => 3600,
],

// The login route has no key yet, so exclude it from signing:
'except' => ['api/login', 'api/register', 'secure-bridge/handshake'],
```

Apply the `secure-bridge` middleware to your protected API routes as usual. The handshake route is authenticated by *your* guard and is auto-excluded from signing.

### Client setup (framework-agnostic)

```js
import SecureBridge from 'secure-bridge-client';

// 1) Log in with your normal auth flow → get { token }
// 2) Handshake (NOT signed; carries the auth token):
await SecureBridge.handshake('/secure-bridge/handshake', {
  headers: { Authorization: `Bearer ${token}` },
});
// 3) Now every same-origin request is signed with the in-memory per-session key:
SecureBridge.installFetch();
```

That's it — `handshake()` calls `configure()` for you with the server-issued key and wire settings.

#### Angular

```ts
// after login resolves with the token:
await SecureBridge.handshake('/secure-bridge/handshake', {
  headers: { Authorization: `Bearer ${token}` },
});
// then your SecureBridgeInterceptor (see INTEGRATION.md) signs everything.
```

#### React / Vue

```js
async function onLoginSuccess(token) {
  await SecureBridge.handshake('/secure-bridge/handshake', {
    headers: { Authorization: `Bearer ${token}` },
  });
  SecureBridge.installFetch();   // or installAxios(axios)
}
```

If a signed request ever comes back **`412 handshake_required`** (e.g. the key TTL expired), just call `handshake()` again and retry.

### Where to keep the key — rules

- ✅ **In a module-scoped variable / app state in memory.** `handshake()` does this for you.
- ❌ **Never** `localStorage`, `sessionStorage`, `IndexedDB`, or a non-HttpOnly cookie. Those are readable by any script (XSS) and persist beyond the session.
- ❌ Never log it, never put it in the URL, never commit it.

## Highest security: the BFF pattern

If you cannot accept *any* browser-held secret, put a thin server-side **Backend-for-Frontend** between the SPA and the API:

- The browser authenticates to the BFF and gets an **HttpOnly, Secure, SameSite cookie** (not readable by JS).
- The BFF holds the SecureBridge key server-side and signs/encrypts requests to the API on the browser's behalf.
- This is the IETF/OWASP-recommended pattern for browser apps handling high-value operations.

In this model the signing layer runs **server-to-server** (use `key_source=static` between BFF and API, both servers, key truly secret), and the browser never holds a usable secret at all.

## Handling XSS / injected scripts ("a script run from the console / network")

First, separate two things people lump together:

1. **A user opening *their own* browser console** and calling `fetch()` / the client to craft requests. This is **not an attack on anyone else** — that person is already authenticated as themselves and can do anything their account allows. No signing scheme can (or should) stop someone acting as themselves; browsers even print a self-XSS warning in the console. Don't design against this — it isn't a vulnerability.
2. **Injected XSS** — attacker-controlled script running inside a **victim's** page (stored/reflected/DOM XSS, or a poisoned npm dependency). This is the real threat, and the honest truth is: **once attacker script runs on your origin it has the same powers your app does** — it can read the in-memory key, ride the auth cookie, and sign requests *while the page is open*.

So the strategy is two layers: **prevent the injection**, and **limit the blast radius** if it still happens.

### Layer 1 — Prevent injection (the only real cure)
- **Strict Content-Security-Policy** with a nonce/hash-based `script-src` — blocks injected and inline scripts. ([web.dev strict-csp](https://web.dev/articles/strict-csp), [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP))
- **Trusted Types** (`Content-Security-Policy: require-trusted-types-for 'script'`) — neutralizes DOM-XSS sinks. ([MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/require-trusted-types-for), [Chrome](https://developer.chrome.com/docs/lighthouse/best-practices/trusted-types-xss)) Chromium-only today, degrades gracefully.
- **Use your framework's auto-escaping** and never bypass it (`innerHTML`, React `dangerouslySetInnerHTML`, Angular `bypassSecurityTrust*`). ([Angular security](https://angular.dev/best-practices/security))
- **Dependency hygiene + Subresource Integrity** — most modern XSS arrives through a compromised package, not your own code.

### Layer 2 — Limit the damage if XSS still happens
- **Non-extractable keys — built in.** Set `signature_driver=ecdsa` with `key_source=token`. The browser generates a non-extractable ECDSA P-256 `CryptoKey`, registers only the **public** key at handshake, and signs with a private key it can never export. Injected script can *use* the key while the page is open but **cannot exfiltrate** it for offline / long-term / replayed abuse — the IETF browser-apps BCP recommendation for DPoP. ([InfoQ](https://www.infoq.com/articles/dpop-key-storage-unsolved-problem/))
  ```env
  SECURE_BRIDGE_KEY_SOURCE=token
  SECURE_BRIDGE_HANDSHAKE=true
  SECURE_BRIDGE_SIGNATURE_DRIVER=ecdsa
  ```
  The client is identical — `await SecureBridge.handshake(url, { headers: { Authorization: 'Bearer '+token } })` auto-generates the keypair and sends the public key. Nothing else changes.
- **Strict CSP + Trusted Types — built in.** Enable `csp.enabled`, apply the `secure-bridge.csp` middleware to your web routes, and put `@cspNonce` on your `<script>` tags. This is *prevention* (Layer 1) shipped with the package; start with `csp.report_only=true` to find violations first.
- **Keep the auth token in an HttpOnly cookie / use a BFF.** XSS can't read an HttpOnly cookie's value (it can still ride it for live requests, but can't steal it). A BFF means no usable secret sits in the browser at all. ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html))
- **Short key TTL + rebind** so a captured key dies fast.
- **Server-side anomaly detection / rate limiting**, since a compromised page's requests still look perfectly valid.

### Bottom line
Request signing/encryption is **not an XSS defense.** It raises the bar — no static key to lift from the bundle, and (with non-extractable keys) no key to steal for offline reuse — but it **cannot protect a page that is already executing attacker code.** The defense against XSS is *preventing XSS*: strict CSP + Trusted Types + framework escaping + dependency hygiene, with a **BFF** for the highest bar.

## Decision guide

- **Internal admin tool / dev / "stop casual tampering and bots"** → `static` is fine. Document it.
- **Server-rendered Blade app with AJAX** → `session` + `@secureBridge`.
- **Decoupled SPA with login** → `token` handshake. (Recommended default for SPAs.)
- **High-value / regulated, can run a proxy** → BFF, browser holds only an HttpOnly cookie.

Whatever you pick, this layer is **defense-in-depth on top of HTTPS and real authentication** — never a replacement for them.
