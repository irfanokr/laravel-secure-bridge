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

**What it does NOT protect against:**

| ❌ Does not stop | Why |
|---|---|
| A determined attacker who reads your JS bundle | The static key is right there — they can sign/encrypt too |
| Anything TLS already covers | This is **defense-in-depth**, not a replacement for HTTPS |
| A compromised browser / XSS on your own site | The key lives in the page; XSS can use it |

**It is therefore a hardening / anti-tampering / anti-automation / log-hygiene layer — never your authentication or authorization.** Keep using real auth (Sanctum, Passport, JWT, session cookies) underneath it.

### Making signing genuinely meaningful

Two supported ways to stop relying on a static bundle key:

1. **Blade per-session keys (recommended for same-origin apps).** When `session_key.enabled` is on, the `@secureBridge` directive mints a **random per-session key server-side** and injects it into the page exactly like the CSRF token. It never lives in a static bundle and rotates per session — so the signature actually proves "this came from an authenticated session in a real browser."
2. **An asymmetric signature driver (Ed25519/ECDSA).** Plug in a driver where the server holds the public key and the client a per-session private key — no shared secret to leak. The driver interface is built for this (see [Custom drivers](#custom-drivers)).

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
| `signature_driver` | `SECURE_BRIDGE_SIGNATURE_DRIVER` | `hmac` | Swappable signature driver. |
| `encryption_driver` | `SECURE_BRIDGE_ENCRYPTION_DRIVER` | `aes-gcm` | Swappable encryption driver. |
| `timestamp_window` | `SECURE_BRIDGE_WINDOW` | `300` | Allowed clock skew (seconds). Never `0`. |
| `replay_protection` | `SECURE_BRIDGE_REPLAY` | `true` | Enforce single-use nonces. |
| `nonce_store` | `SECURE_BRIDGE_NONCE_STORE` | `null` | Cache store for nonces (use Redis in prod). |
| `response_mode` | `SECURE_BRIDGE_RESPONSE_MODE` | `field` | `field` (encrypt one key) or `full`. |
| `response_key` | `SECURE_BRIDGE_RESPONSE_KEY` | `data` | Field to encrypt in `field` mode. |
| `only` / `except` | — | see file | Path patterns to scope global usage. |
| `bypass.*` | `SECURE_BRIDGE_BYPASS_TOKEN` | — | Let trusted/native clients skip the layer. |
| `skip_multipart` | — | `true` | Skip `multipart/form-data` uploads. |
| `session_key.enabled` | `SECURE_BRIDGE_SESSION_KEY` | `false` | Per-session keys for Blade apps. |
| `debug` | `SECURE_BRIDGE_DEBUG` | `false` | Log *why* a signature failed (dev only). |

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
