# Laravel Secure Bridge

[![Packagist](https://img.shields.io/packagist/v/irfanokr/laravel-secure-bridge.svg)](https://packagist.org/packages/irfanokr/laravel-secure-bridge)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A drop-in security layer between a JavaScript front-end and a Laravel API that adds, with independent on/off switches:

- **Request signing** — HMAC-SHA256 over `method + path + query + timestamp + nonce + body-digest`, modeled on RFC 9421 / AWS SigV4 / Stripe webhook signatures.
- **Replay protection** — a bounded timestamp window **plus** a single-use nonce cache (Redis-friendly, so it works across multiple servers).
- **Request body encryption** — optional AES-256-GCM of the POST/PUT/PATCH/DELETE body.
- **Response encryption** — optional AES-256-GCM of the JSON response (a single field, or the whole body).

It ships with a **framework-agnostic JavaScript client** (`fetch`, `axios`, `jQuery`, Angular, React, Vue) and works with **Laravel 5.5 → 12** on **PHP 7.1+**.

Standard, audited primitives only — AES-256-GCM via `openssl`/Web Crypto and HMAC-SHA256. No hand-rolled ciphers.

> 🟢 **New to this / want the shortest path?** Start with the **[5-minute beginner guide → docs/QUICKSTART.md](docs/QUICKSTART.md)**. It walks you through the simplest working setup in plain language — no crypto knowledge needed. Come back here for the details.

---

## Threat model — read this first

This is the section every comparable package leaves out, and it is the most important one.

**A public SPA cannot hold a secret.** Any key you put in a downloadable JavaScript bundle can be read by anyone who opens the bundle. This is the consensus position of OWASP, the IETF OAuth browser-based-apps BCP, and every serious browser-security writeup. So be precise about what this layer does and does not buy you.

**What it protects against (on top of HTTPS):**

| ✅ Protects | How |
|---|---|
| Request **tampering** in transit / by intermediaries | HMAC over a canonical request; any change invalidates it |
| **Replay** of a captured request | Timestamp window + single-use nonce |
| Casual **bots / scrapers** that don't execute or read your JS | They can't produce a valid signature |
| **Payload exposure** in server logs, APM/observability tools, browser extensions, and TLS-terminating corporate proxies | AES-256-GCM end-to-end between browser and PHP |
| Accidental misuse of endpoints by tools that skip the handshake | Rejected with a clear error |

**What it does NOT *fully* stop — and how the package shrinks each gap:**

| ❌ Limitation | Why it exists | ✅ How the package reduces it |
|---|---|---|
| A **static key** in a downloadable bundle isn't secret | It's right there in the JS — anyone can read and reuse it | Don't ship a static key. Use `key_source=token` (the key never enters the bundle and is different per session) or `session` (Blade). With `signature_driver=ecdsa` the signing key is **non-extractable** — it can't be read or copied out *at all*. |
| Anything **TLS already covers** | This is **defense-in-depth**, not a replacement for HTTPS | Keep HTTPS on (`require_https=true`). This layer *adds to* TLS; it never replaces it. |
| **XSS on your own site** — injected script can *use* whatever the open page can | Attacker script runs with your page's privileges while the page is open | Signing can't cure XSS, but the package narrows it: (a) the bundled **CSP + Trusted Types** helper *prevents* most XSS; (b) `ecdsa` non-extractable keys mean injected script can't *steal* the key for offline/replay reuse; (c) short key TTL + a **BFF** shrink the window further. Full playbook → [docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md). |

**Bottom line:** it's a hardening / anti-tampering / anti-automation / log-hygiene layer — **never** your authentication or authorization. Keep real auth (Sanctum, Passport, JWT, session cookies) underneath it.

### Making signing genuinely meaningful

> 📕 **Full guide: [docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md)** — how to use this safely in a decoupled JS framework, with all four key sources and the honest limits.

Don't ship a static key in a public SPA bundle. Choose a `key_source` instead:

1. **`token` — per-session keys for decoupled SPAs (recommended).** Set `key_source=token` + `handshake.enabled=true`. After login the SPA calls `SecureBridge.handshake('/secure-bridge/handshake', { headers: { Authorization: 'Bearer '+token } })`; the server mints a random key bound to that token and returns it once; the client keeps it **in memory only**. No key in the bundle, a different key per session, useless to anyone reading your JS.
2. **`session` — Blade per-session keys (recommended for same-origin apps).** `@secureBridge` mints a random per-session key server-side and injects it like the CSRF token — never in a static bundle.
3. **Asymmetric, non-extractable keys (`signature_driver=ecdsa`, strongest for XSS).** With `key_source=token`, the browser generates a **non-extractable ECDSA P-256 keypair**, registers only the public key at handshake, and signs with a private key it can never export — so injected XSS cannot steal the signing key for offline reuse. No shared secret at all.
4. **BFF** — for the highest bar, keep the key server-side entirely and give the browser only an HttpOnly cookie (see the guide).

To *prevent* XSS in the first place, enable the bundled **CSP + Trusted Types** helper: set `csp.enabled` and apply the `secure-bridge.csp` middleware to your web routes, then put `@cspNonce` on your `<script>` tags. See [docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md).

---

## Installation

### Server (Laravel)

```bash
composer require irfanokr/laravel-secure-bridge
php artisan secure-bridge:keygen          # writes SECURE_BRIDGE_KEY to .env
php artisan vendor:publish --tag=secure-bridge-config
```

On Laravel 5.5+ the service provider and `SecureBridge` facade are auto-discovered. On older versions, register `Irfanokr\SecureBridge\SecureBridgeServiceProvider` manually.

Apply the middleware to the routes you want protected:

```php
// routes/api.php
Route::middleware('secure-bridge')->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
    // ...
});
```

**Per-route feature selection** — pick exactly which features apply on a route (anything not named is off), so a developer can enable some and skip others:

```php
Route::middleware('secure-bridge:sign')->post('/api/login', ...);              // sign only
Route::middleware('secure-bridge:sign,encrypt-response')->get('/api/me', ...); // sign + encrypt response
Route::middleware('secure-bridge:encrypt,https')->post('/api/secret', ...);    // encrypt both + require HTTPS
Route::middleware('secure-bridge:all')->post('/api/transfer', ...);            // everything
```

Tokens: `sign`, `encrypt-request`, `encrypt-response`, `encrypt`, `all`, `https`, `no-https`. With no token it uses the config defaults. See **[docs/EXAMPLES.md](docs/EXAMPLES.md)** for copy-paste AJAX and Angular code.

Or globally (and scope it with the `only`/`except` config):

```php
// app/Http/Kernel.php  ->  $middlewareGroups['api']
\Irfanokr\SecureBridge\Http\Middleware\SecureBridgeMiddleware::class,
```

### Client (browser)

```bash
npm install secure-bridge-client
```

…or, for a same-origin Blade app, publish the prebuilt client and drop in the Blade directive (no build step):

```bash
php artisan vendor:publish --tag=secure-bridge-assets   # -> public/vendor/secure-bridge
```

---

## Quick start

### Decoupled SPA (React / Angular / Vue / anything)

```js
import SecureBridge from 'secure-bridge-client';

SecureBridge.configure({
  key: 'BASE64_MASTER_KEY',     // the base64 part of SECURE_BRIDGE_KEY
  sign: true,
  encryptRequest: false,        // flip on as needed
  encryptResponse: false,
});

SecureBridge.installFetch();    // transparently sign same-origin fetch() calls
```

### Same-Laravel Blade app + AJAX (the strong, per-session story)

```env
SECURE_BRIDGE_SESSION_KEY=true
```

```blade
{{-- in your layout <head>, after jQuery if you use it --}}
@secureBridge
```

That injects the client and a **per-session** key, and auto-wires `window.fetch` and (if present) `jQuery`. Your existing `fetch`/`$.ajax` login and form posts are now signed with a key that is *not* in any static bundle.

---

## Configuration

`config/secure-bridge.php` (every value is env-overridable):

| Key | Env | Default | Purpose |
|---|---|---|---|
| `key` | `SECURE_BRIDGE_KEY` | — | Master secret (`base64:…`). Sign/enc sub-keys are HKDF-derived from it. |
| `previous_keys` | `SECURE_BRIDGE_PREVIOUS_KEYS` | `[]` | Old keys accepted during rotation. |
| `sign_requests` | `SECURE_BRIDGE_SIGN` | `true` | Verify HMAC + timestamp + nonce. |
| `encrypt_request` | `SECURE_BRIDGE_ENCRYPT_REQUEST` | `false` | Decrypt the request body. |
| `encrypt_response` | `SECURE_BRIDGE_ENCRYPT_RESPONSE` | `false` | Encrypt the response. |
| `signature_driver` | `SECURE_BRIDGE_SIGNATURE_DRIVER` | `hmac` | `hmac` or `ecdsa` (non-extractable browser keypair; needs `key_source=token`). |
| `key_source` | `SECURE_BRIDGE_KEY_SOURCE` | `static` | `static` / `session` (Blade) / `token` (SPA handshake). See [SECURING-THE-KEY](docs/SECURING-THE-KEY.md). |
| `handshake.*` | `SECURE_BRIDGE_HANDSHAKE` | off | Per-session key endpoint for SPAs (route, auth middleware, TTL). |
| `csp.*` | `SECURE_BRIDGE_CSP` | off | Strict CSP + Trusted Types via the `secure-bridge.csp` middleware (XSS prevention). |
| `encryption_driver` | `SECURE_BRIDGE_ENCRYPTION_DRIVER` | `aes-gcm` | Swappable encryption driver. |
| `timestamp_window` | `SECURE_BRIDGE_WINDOW` | `300` | Allowed clock skew (seconds). Never `0`. |
| `replay_protection` | `SECURE_BRIDGE_REPLAY` | `true` | Enforce single-use nonces. |
| `nonce_store` | `SECURE_BRIDGE_NONCE_STORE` | `null` | Cache store for nonces (use Redis in prod). |
| `response_mode` | `SECURE_BRIDGE_RESPONSE_MODE` | `field` | `field` (encrypt one key) or `full`. |
| `response_key` | `SECURE_BRIDGE_RESPONSE_KEY` | `data` | Field to encrypt in `field` mode. |
| `only` / `except` | — | see file | URI patterns to exclude (mirrors Laravel's CSRF `$except`). The only bypass — no header/client-type bypass exists. |
| `sign_multipart` | `SECURE_BRIDGE_SIGN_MULTIPART` | `true` | Sign `multipart/form-data` uploads body-less (so they can't bypass the layer). Body is never encrypted. |
| `require_https` | `SECURE_BRIDGE_REQUIRE_HTTPS` | `false` | Reject non-HTTPS requests (localhost exempt). |
| `session_key.enabled` | `SECURE_BRIDGE_SESSION_KEY` | `false` | Per-session keys for Blade apps. |
| `debug` | `SECURE_BRIDGE_DEBUG` | `false` | Log *why* a signature failed (dev only). |
| `events` | `SECURE_BRIDGE_EVENTS` | `true` | Dispatch a `RequestBlocked` event on every rejection (for logging/alerting). |

---

## Framework adapters

📖 **Full, version-specific integration guide:** [docs/INTEGRATION.md](docs/INTEGRATION.md) — AngularJS 1.x, Angular 2–14 (class interceptor), Angular 15+ (functional interceptor), React, Vue 2, Vue 3, Svelte/SvelteKit, jQuery/AJAX, vanilla JS, and Node.

The client core is async (Web Crypto is async). `installFetch()` covers most apps. Other clients:

**axios** (put query params in the URL string, not `config.params`):
```js
import axios from 'axios';
SecureBridge.configure({ key: '…' });
SecureBridge.installAxios(axios);
```

**jQuery:**
```js
SecureBridge.configure({ key: '…' });
SecureBridge.installJQuery(window.jQuery);
$.secureAjax({ url: '/api/login', type: 'POST', data: { username: 'demo' } })
  .then(data => { /* already decrypted if encryptResponse is on */ });
```

**Angular** (`HttpInterceptor`):
```ts
import { from } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import SecureBridge from 'secure-bridge-client';

intercept(req: HttpRequest<any>, next: HttpHandler) {
  return from(SecureBridge.prepare(req.method, req.urlWithParams, req.body)).pipe(
    switchMap(p => next.handle(req.clone({
      setHeaders: p.headers,
      body: p.body ?? req.body,
    })))
  );
}
```

**React / Vue:** call `SecureBridge.installFetch()` once at startup, or use `SecureBridge.prepare(...)` before any custom request. Decrypt responses with `SecureBridge.processResponse(json)` if you aren't using `installFetch`.

**Signed file downloads** (browser navigations can't set headers):
```js
const url = await SecureBridge.signUrl('/api/report/export?year=2026');
window.open(url, '_blank');
```

---

## Wire format (v1)

```
keys      signKey = HKDF-SHA256(master, info="secure-bridge:sign:v1", 32 bytes)
          encKey  = HKDF-SHA256(master, info="secure-bridge:enc:v1",  32 bytes)

canonical METHOD \n PATH \n QUERY \n TIMESTAMP \n NONCE \n sha256hex(rawBody)
signature header  X-Sig: v1=<hmac_sha256_hex(signKey, canonical)>
          plus    X-Timestamp: <unix-seconds>,  X-Nonce: <random hex>
          (or query params __sb_sig / __sb_ts / __sb_nonce for downloads)

envelope  v1.<base64(iv[12])>.<base64(ciphertext || gcmTag[16])>
          AES-256-GCM, AAD = "secure-bridge:v1"
          request body becomes  {"__cipher":"<envelope>"}
```

`php artisan secure-bridge:doctor` prints a **deterministic conformance test vector** (canonical string + expected `X-Sig`) so a client developer can confirm their implementation matches the server byte-for-byte. This kills the #1 integration headache — "invalid signature" with no clue why. Pair it with `SECURE_BRIDGE_DEBUG=true` to log the exact canonical mismatch in your local env.

---

## Key rotation

```env
SECURE_BRIDGE_KEY=base64:NEWKEY...
SECURE_BRIDGE_PREVIOUS_KEYS=base64:OLDKEY...
```

New traffic is signed/encrypted with the current key; the previous keys are still **accepted** for verification and decryption, so clients can update without downtime.

---

## Custom drivers

Bind your own and select it by name in config:

```php
// a service provider
$this->app->bind('secure-bridge.signature.ed25519', Ed25519SignatureDriver::class);
```
```env
SECURE_BRIDGE_SIGNATURE_DRIVER=ed25519
```

Implement `Irfanokr\SecureBridge\Contracts\SignatureDriver` or `EncryptionDriver`.

---

## Notes & limitations (by design)

- **Response encryption scope.** `field` mode (default) encrypts only the configured key (`data`); other keys and error bodies are sent as-is. Use `response_mode=full` to encrypt the whole JSON body (covers errors too). Streamed / binary / file responses are never encrypted.
- **Reading the decrypted body.** Controllers read decrypted fields via `$request->input()` / `all()` / `validated()`. `$request->getContent()` still returns the raw (encrypted) body — code that reads the raw stream directly should use the input bag instead.
- **Header integrity.** The signature covers method, path, query, timestamp, nonce and a body digest — not arbitrary headers. `Authorization` is validated by your auth layer; if you need a specific header bound into the signature, supply a custom signature driver.
- **Transport.** Always run behind HTTPS (set `require_https=true`); this layer is defense-in-depth on top of TLS, never a replacement.

## How this compares

| | This package | `kbs1/laravel-encrypted-api` | `tzsk/crypton` |
|---|---|---|---|
| Request signing + replay | ✅ | partial (10s id) | ❌ |
| Optional encryption (independent toggles) | ✅ | always on | always on |
| Browser client shipped | ✅ (fetch/axios/jQuery/SPA) | ❌ | partial |
| Documented threat model | ✅ | ❌ | ❌ |
| Per-session key option | ✅ | ❌ | ❌ |
| Standard AES-256-GCM | ✅ | undocumented | undocumented |
| Laravel support | 5.5 → 12 | abandoned (5.4) | 7 / 8 |

---

## Requirements

- PHP **7.1+** with `ext-openssl` (AES-256-GCM) and `ext-json`.
- Laravel **5.5 → 12**.
- Browser with the Web Crypto API in a **secure context** (HTTPS or `localhost`).

## License

[MIT](LICENSE).
