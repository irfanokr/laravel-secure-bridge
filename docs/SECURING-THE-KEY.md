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

## Decision guide

- **Internal admin tool / dev / "stop casual tampering and bots"** → `static` is fine. Document it.
- **Server-rendered Blade app with AJAX** → `session` + `@secureBridge`.
- **Decoupled SPA with login** → `token` handshake. (Recommended default for SPAs.)
- **High-value / regulated, can run a proxy** → BFF, browser holds only an HttpOnly cookie.

Whatever you pick, this layer is **defense-in-depth on top of HTTPS and real authentication** — never a replacement for them.
