# Front-end integration guide (separate front-end apps)

This is the **client-side** detail for a **separate** front-end — React, Angular, Vue, Svelte, plain JavaScript, or Node — that calls a Laravel API.

> Using Laravel **Blade** pages instead? You don't need this file. The `@secureBridge` directive wires everything for you — see **[README → Section A](../README.md#a--server-rendered-laravel-blade)**.

The matching **server** setup is in **[README → Section B](../README.md#b--separate-front-end--laravel-api)**. Read that first; this guide picks up on the browser side.

---

## The one call (recommended): `SecureBridge.start()`

```js
import SecureBridge from 'secure-bridge-client';   // npm install secure-bridge-client

SecureBridge.start({
  handshake: '/secure-bridge/handshake',
  token: () => localStorage.getItem('auth_token'),   // however your app stores its login token
});
```

Call this **once**, where your app boots. From then on **every same-origin request is signed automatically** — `fetch`, `axios`, `jQuery`, and Angular's `HttpClient` (they all use `fetch`/`XMLHttpRequest` underneath). You never edit a single request, no matter how many you have.

**What `start()` does for you — so you don't have to:**

- **Gets the key lazily.** The first request that carries a token triggers the *handshake* (one request that fetches this session's signing key from the server). No need to wire anything into your login flow.
- **No reload wiring.** The key lives in memory and is gone after a page reload — but your login token survives, so the next request just fetches a fresh key. You write nothing for this.
- **No `412` handling.** The key is renewed **before** it expires and **re-fetched if your login token changes**, so an expired-key `412` essentially never reaches your code. (As a safety net, a `fetch` that still gets a `412` re-handshakes and retries once, transparently.)
- **No token → unsigned.** If `token()` returns nothing (the user isn't logged in yet), the request is sent **unsigned** — so public and login routes keep working and no handshake is attempted before login.
- **One handshake under load.** If several requests fire at once on first load, they share a single handshake.

### Options

| Option | Required | Meaning |
|---|---|---|
| `handshake` | yes | Your server handshake endpoint, e.g. `'/secure-bridge/handshake'`. |
| `token` | recommended | The current auth token — a **function** (read fresh each request, so rotation is picked up) or a string. Return `null`/empty when logged out. |
| `onError` | no | Called if a handshake fails; the request then proceeds unsigned. |
| `handshakeInit` | no | Extra `fetch` init merged into the handshake call, e.g. `{ credentials: 'include' }` for a cookie/CORS setup. |
| `refreshMargin` | no | Milliseconds before the server TTL to renew the key (default `30000`). |
| `global` | no | Target global to patch (defaults to `window`). |

> **Same-origin note:** signing applies to **same-origin** requests. If your API is on a *different* origin than your front-end, requests to it are cross-origin — see [Cross-origin APIs](#cross-origin-apis) below.

---

## Where the one call goes, per framework

It's the **same call** everywhere — only *where you put it* differs. Put it once, at startup.

### React

```jsx
// src/secure-bridge.js
import SecureBridge from 'secure-bridge-client';
SecureBridge.start({
  handshake: '/secure-bridge/handshake',
  token: () => localStorage.getItem('auth_token'),
});
```
```jsx
// src/index.jsx — import it once, before you render:
import './secure-bridge';
```

### Vue (3 and 2)

```js
// main.js — before createApp(...).mount(...)
import SecureBridge from 'secure-bridge-client';
SecureBridge.start({
  handshake: '/secure-bridge/handshake',
  token: () => localStorage.getItem('auth_token'),
});
```

### Angular

`start()` already signs every `HttpClient` request (it uses `XMLHttpRequest`), so you do **not** need an interceptor just to sign. Put the call at the top of `main.ts`:

```ts
// main.ts — before bootstrapApplication(...) / platformBrowserDynamic()...
import SecureBridge from 'secure-bridge-client';
SecureBridge.start({
  handshake: '/secure-bridge/handshake',
  token: () => localStorage.getItem('auth_token'),
});
```

(Only if you enable `encrypt_response` and want replies decrypted automatically, add the interceptor under [Response decryption](#response-decryption).)

### Svelte / SvelteKit

```js
// a client-only module imported in your root +layout
import { browser } from '$app/environment';
import SecureBridge from 'secure-bridge-client';
if (browser) {
  SecureBridge.start({
    handshake: '/secure-bridge/handshake',
    token: () => localStorage.getItem('auth_token'),
  });
}
```

> SSR note: only call it in the browser — never during server-side rendering.

### Plain JavaScript (no build tools)

```html
<script src="https://unpkg.com/secure-bridge-client"></script>
<script>
  SecureBridge.start({
    handshake: '/secure-bridge/handshake',
    token: function () { return localStorage.getItem('auth_token'); },
  });
</script>
```

### jQuery

`start()` already covers jQuery (it uses `XMLHttpRequest`). After it runs once, your existing `$.ajax` / `$.get` / `$.post` / `$.getJSON` calls are signed — **nothing else to wire**.

### Node.js / server-to-server

Server-to-server typically uses a **`static` shared key** (both ends are servers, so the key is genuinely secret — no handshake/`start()` needed):

```js
const SecureBridge = require('secure-bridge-client');   // Node 18+ (global Web Crypto)
SecureBridge.configure({ key: process.env.SB_KEY, sign: true });

const p = await SecureBridge.prepare('POST', 'https://api.example.com/api/sync', { ok: true });
await fetch(p.url, { method: p.method, headers: p.headers, body: p.body });
```

---

<a id="response-decryption"></a>
## Response decryption (only if `encrypt_response` is on)

`start()` signs every request and auto-decrypts responses **for `fetch`**. For XHR-based libraries (axios / jQuery / Angular) either call `SecureBridge.processResponse(reply)` on the data you receive, or register an interceptor that does it for you.

**axios** — one call adds request signing *and* response decryption:

```js
SecureBridge.installAxios(axios);   // put query params in the URL string, not config.params
```

**Angular** — an interceptor that signs *and* decrypts (use it instead of relying on `start()`'s signing if you prefer the Angular-native way). Pick the form for your version:

```ts
// Angular 4.3–18: class interceptor — secure-bridge.interceptor.ts
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpResponse } from '@angular/common/http';
import { Observable, from, of } from 'rxjs';
import { switchMap, mergeMap, map } from 'rxjs/operators';
import SecureBridge from 'secure-bridge-client';

@Injectable()
export class SecureBridgeInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return from(SecureBridge.prepare(req.method, req.urlWithParams, req.body)).pipe(
      switchMap((p) => {
        const cloned = p.body !== undefined
          ? req.clone({ setHeaders: p.headers, body: p.body })   // send the exact signed string
          : req.clone({ setHeaders: p.headers });
        return next.handle(cloned).pipe(
          mergeMap((event: HttpEvent<any>) =>
            event instanceof HttpResponse && event.body && typeof event.body === 'object'
              ? from(SecureBridge.processResponse(event.body)).pipe(map((b) => event.clone({ body: b })))
              : of(event)
          )
        );
      })
    );
  }
}
```
```ts
// register it (NgModule):
{ provide: HTTP_INTERCEPTORS, useClass: SecureBridgeInterceptor, multi: true }
```
```ts
// Angular 15+: functional interceptor
import { HttpInterceptorFn, HttpResponse } from '@angular/common/http';
import { from, of } from 'rxjs';
import { switchMap, mergeMap, map } from 'rxjs/operators';
import SecureBridge from 'secure-bridge-client';

export const secureBridgeInterceptor: HttpInterceptorFn = (req, next) =>
  from(SecureBridge.prepare(req.method, req.urlWithParams, req.body)).pipe(
    switchMap((p) => {
      const cloned = p.body !== undefined
        ? req.clone({ setHeaders: p.headers, body: p.body })
        : req.clone({ setHeaders: p.headers });
      return next(cloned).pipe(
        mergeMap((event) =>
          event instanceof HttpResponse && event.body && typeof event.body === 'object'
            ? from(SecureBridge.processResponse(event.body)).pipe(map((b) => event.clone({ body: b })))
            : of(event)
        )
      );
    })
  );
// register: provideHttpClient(withInterceptors([secureBridgeInterceptor]))
```

If you use an interceptor that calls `prepare()` directly, you still need the signing key — call `start()` (or the manual `handshake()` below) so the key is available.

---

## File uploads

`FormData` bodies are **still signed** (over the method + path + query + timestamp + nonce, with an empty body digest — so a request can't skip the layer by claiming a multipart `Content-Type`); only *encryption* of the body is skipped, because the browser owns the multipart boundary. Just pass the `FormData` as the body as usual.

---

<a id="signed-get-query"></a>
## Signed GETs and the query-string gotcha

The signed path+query must equal what the browser actually sends.

- With `fetch` and Angular `urlWithParams` this is automatic.
- With **axios `config.params`** or **jQuery `data` on a GET**, params are serialized *after* signing — so put them **in the URL string** instead, or use `SecureBridge.signUrl(url)` for download links / `window.open`.

---

<a id="cross-origin-apis"></a>
## Cross-origin APIs

Signing applies to **same-origin** requests (the common case: your front-end and API share an origin, or you proxy the API under the same origin in dev). If your API genuinely lives on a different origin:

- Requests to it are cross-origin and pass through **unsigned** by design (the package never attaches your `Authorization`/signature to a third-party origin).
- Serve the API under the same origin (a reverse proxy, or a dev proxy such as Vite/CRA `proxy`) so signing applies, **or** use the [BFF pattern](SECURING-THE-KEY.md) where a same-origin backend signs server-to-server.
- For a cross-site cookie-based handshake, pass `handshakeInit: { credentials: 'include' }` to `start()` and enable CORS credentials on the server.

---

## Advanced: manual control (`handshake()` then `install()`)

`start()` is the recommended path. If you want explicit control — or you're not using token mode — you can drive the two underlying calls yourself.

```js
// 1. after login (you have a fresh token), get this session's key:
await SecureBridge.handshake('/secure-bridge/handshake', {
  headers: { Authorization: 'Bearer ' + token },
});
// 2. turn on signing for every request:
SecureBridge.install();
```

With the manual pattern **you** own the lifecycle:

- **Call it at login AND at startup.** The key lives in memory, so a page reload wipes it; re-run the two calls on app load when a saved token exists.
- **Handle `412` yourself.** If a request returns `412 handshake_required` (the key expired or the token rotated), re-handshake and retry:

  ```js
  async function apiFetch(url, init, token) {
    let res = await fetch(url, init);
    if (res.status === 412) {                 // key expired → re-handshake, retry once
      await SecureBridge.handshake('/secure-bridge/handshake', { headers: { Authorization: 'Bearer ' + token } });
      SecureBridge.install();
      res = await fetch(url, init);
    }
    return res;
  }
  ```

`start()` does all of the above for you — prefer it unless you have a specific reason not to.

### Static key mode (no login — anti-tampering only)

If your app has **no login** and you only want anti-tampering / bot-deterrence (**not** real secrecy), skip the handshake and use a build-time key:

```js
SecureBridge.configure({ key: import.meta.env.VITE_SB_KEY, sign: true });
SecureBridge.install();
```

> ⚠️ A key in downloadable JavaScript is **not secret** — anyone can read it. Use this only for low-stakes/internal cases. For anything sensitive, use `start()` (the handshake). Full reasoning: **[SECURING-THE-KEY.md](SECURING-THE-KEY.md)**.

---

## Works with your existing auth (JWT, Sanctum, Passport, sessions)

This package is **independent of how you authenticate** — it layers on top.

- Set `handshake.middleware` (server config) to **your** guard: `auth:sanctum`, `auth:api` (JWT), `jwt.auth` (tymon/jwt-auth), Passport, etc. That guard protects the handshake endpoint.
- The handshake binds the signing key to the **bearer token** you send it. So every request carries `Authorization: Bearer <token>` (checked by **your** auth) and the `X-Sig` signature (checked by **this package**) — two independent layers; order doesn't matter.
- **Token refresh / rotation (common with JWT):** when the token changes, `start()` automatically re-handshakes with the new token (because `token()` is read fresh each request). With the manual pattern, re-run `handshake()` after you refresh.

---

<a id="config-reference"></a>
## Full configuration reference

Publish the config with `php artisan vendor:publish --tag=secure-bridge-config`. Every value can also be set in `.env`.

| Setting | `.env` variable | Default | What it does |
|---|---|---|---|
| `key` | `SECURE_BRIDGE_KEY` | — | Your secret key (created by `secure-bridge:keygen`). |
| `previous_keys` | `SECURE_BRIDGE_PREVIOUS_KEYS` | `[]` | Old keys still accepted during a key change. |
| `sign_requests` | `SECURE_BRIDGE_SIGN` | `true` | Turn signing on/off. |
| `encrypt_request` | `SECURE_BRIDGE_ENCRYPT_REQUEST` | `false` | Scramble what the browser sends. |
| `encrypt_response` | `SECURE_BRIDGE_ENCRYPT_RESPONSE` | `false` | Scramble what the server replies. |
| `signature_driver` | `SECURE_BRIDGE_SIGNATURE_DRIVER` | `hmac` | `hmac` (normal) or `ecdsa` (non-stealable key). |
| `key_source` | `SECURE_BRIDGE_KEY_SOURCE` | `static` | Where the key comes from: `static` / `session` (Blade) / `token` (separate app). |
| `handshake.*` | `SECURE_BRIDGE_HANDSHAKE` | off | The "give the browser a key after login" endpoint for separate apps. |
| `handshake.ttl` | `SECURE_BRIDGE_HANDSHAKE_TTL` | `3600` | Seconds a handshake-issued key is valid (sent to the client as `expiresIn`; `start()` renews before this). |
| `csp.*` | `SECURE_BRIDGE_CSP` | off | The built-in anti-XSS (CSP + Trusted Types) helper. |
| `timestamp_window` | `SECURE_BRIDGE_WINDOW` | `300` | How many seconds of clock difference to allow. |
| `replay_protection` | `SECURE_BRIDGE_REPLAY` | `true` | Block the same request from being sent twice. |
| `nonce_store` | `SECURE_BRIDGE_NONCE_STORE` | `null` | Where to remember used requests (use Redis in production). |
| `response_mode` | `SECURE_BRIDGE_RESPONSE_MODE` | `field` | Scramble one field (`field`) or the whole reply (`full`). |
| `response_key` | `SECURE_BRIDGE_RESPONSE_KEY` | `data` | Which field to scramble in `field` mode. |
| `only` / `except` | — | see file | Which URLs to include / skip. |
| `sign_multipart` | `SECURE_BRIDGE_SIGN_MULTIPART` | `true` | Sign file uploads too (so they can't sneak past). |
| `require_https` | `SECURE_BRIDGE_REQUIRE_HTTPS` | `false` | Reject non-HTTPS requests (localhost is allowed). |
| `session_key.enabled` | `SECURE_BRIDGE_SESSION_KEY` | `false` | The simple Blade setup (a fresh key per visitor). |
| `debug` | `SECURE_BRIDGE_DEBUG` | `false` | While developing, log *why* a request was refused. |
| `events` | `SECURE_BRIDGE_EVENTS` | `true` | Fire an event whenever a request is blocked (for logging/alerts). |

---

<a id="refusal-codes"></a>
## When a request is refused — what the codes mean

With `start()` the `412` case is handled for you, so this table is mainly for the manual pattern and for debugging.

| Code you see | What it means | What to do |
|---|---|---|
| `412 handshake_required` | (separate-app setup) the browser hasn't got its key yet, or it expired | `start()` re-handshakes automatically; with the manual pattern, call `handshake()` again and retry |
| `400 missing_signature` | the route is protected but the request wasn't signed | make sure `@secureBridge` (Blade) or `start()` / `install()` (separate app) ran before the request, and that the request has a token |
| `400 invalid_signature` | the fingerprint didn't match | for jQuery/axios **GET**s, put the query values in the URL, not a separate `data`/`params` object (see [the query gotcha](#signed-get-query)) |
| `400 stale_timestamp` | the device clock is more than 5 minutes off | fix the clock, or raise `SECURE_BRIDGE_WINDOW` |
| `409 replay` | the same signed request was sent twice | each request can only be used once — don't resend the identical one |
| handshake route returns `401`/`404` | the handshake endpoint isn't reachable or your guard rejected it | confirm `SECURE_BRIDGE_HANDSHAKE=true`, the `handshake.middleware` guard matches your login, and the route isn't blocked |

Tip: set `SECURE_BRIDGE_DEBUG=true` while developing and the log tells you exactly what went wrong.

---

## Log or alert when a request is blocked (observability)

Every rejection fires an event (metadata only — never the payload). Listen for it to log or alert:

```php
use Irfanokr\SecureBridge\Events\RequestBlocked;
use Illuminate\Support\Facades\Event;

Event::listen(RequestBlocked::class, function (RequestBlocked $e) {
    logger()->warning('SecureBridge blocked a request', [
        'code'   => $e->code,    // e.g. missing_signature, replay
        'status' => $e->status,  // e.g. 400, 409, 412
        'ip'     => $e->request->ip(),
        'path'   => $e->request->path(),
    ]);
});
```

Toggle with the `events` config (on by default).

---

## Verify your wiring

- Run **`php artisan secure-bridge:doctor`** on the server — it prints your settings and a sample signature (a conformance vector a client developer can reproduce).
- Set **`SECURE_BRIDGE_DEBUG=true`** locally to log exactly why a signature failed.
- **Clock skew:** the client uses the browser clock for the timestamp. A device clock off by more than `timestamp_window` (default 300s) is rejected — sync the clock or widen the window.

---

## Technical details — what's on the wire

The fingerprint is an HMAC-SHA256 over a canonical string, and encryption is AES-256-GCM (standard, audited building blocks — nothing hand-rolled):

```
canonical = METHOD \n PATH \n QUERY \n TIMESTAMP \n NONCE \n sha256hex(body)
header    X-Sig: v1=<hmac_sha256_hex(signKey, canonical)>
          X-Timestamp, X-Nonce   (or __sb_sig / __sb_ts / __sb_nonce for download links)
envelope  v1.<base64(iv)>.<base64(ciphertext+tag)>   (AES-256-GCM, AAD "secure-bridge:v1")
```

You can swap in your own signing or encryption method by binding a driver:

```php
$this->app->bind('secure-bridge.signature.ed25519', Ed25519SignatureDriver::class);
```
```env
SECURE_BRIDGE_SIGNATURE_DRIVER=ed25519
```

Implement `Irfanokr\SecureBridge\Contracts\SignatureDriver` or `EncryptionDriver`.

---

## Exactly which requests get signed?

`start()`/`install()` hooks the browser's two request engines — `fetch` and `XMLHttpRequest` — so it catches every request **regardless of the library**, because they all use one of those two underneath.

**Signed automatically (✅):** `fetch`, raw `XMLHttpRequest`, jQuery (`$.ajax`/`$.get`/`$.post`/`$.getJSON`), axios, Angular `HttpClient`, and anything built on them (react-query, SWR, …).

**Not signed (rare, none are normal API calls) (❌):** `navigator.sendBeacon()` (use `signUrl()` if needed), **JSONP** (a `<script>` include, not a request), WebSocket / Server-Sent Events (authenticate the socket separately), and native `<form>` submits / full-page navigations (use `signUrl()` for a signed download link).

---

## Glossary — the words in these docs, in plain English

| Word | Plain meaning |
|---|---|
| **Signature / "fingerprint"** | A short code attached to each request (the `X-Sig` header) that the server recomputes to check the request is genuine and unchanged. |
| **Sign a request** | Attach that fingerprint so the server will accept it. |
| **Handshake** | One request your app makes to get its signing key from the server. |
| **Per-session key** | A signing key that's different for every logged-in session and is thrown away when the session ends. |
| **Bearer token** | Your app's normal login token, sent in the `Authorization: Bearer …` header. |
| **Nonce** | A random value used once per request, so a captured request can't be replayed later. |
| **Replay** | Capturing a valid request and sending it again later; blocked because each request is single-use. |
| **Timestamp window** | How far the device clock may differ from the server (default 5 min) before a request is rejected. |
| **Canonical string** | The exact text (method + path + query + timestamp + nonce + body) that both sides build identically to compute/verify the signature. |
| **HMAC** | The normal signing method — one shared key signs and verifies. |
| **ECDSA (non-extractable key)** | A stronger option: the browser holds a key it can *use* but JavaScript can never read or copy out (so even malicious script can't steal it). |
| **Encryption (AES-256-GCM)** | Optional scrambling of the request/response contents so onlookers (logs, proxies, extensions) can't read them. |
| **BFF (Backend-for-Frontend)** | An optional small server between your browser and API so the key never lives in the browser at all — the highest-security setup. |
| **Multipart (signed "body-less")** | File uploads are still signed, but the file bytes themselves aren't part of the signature (the browser controls that format). |
