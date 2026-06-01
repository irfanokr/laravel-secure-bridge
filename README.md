# Laravel Secure Bridge

[![Packagist](https://img.shields.io/packagist/v/irfanokr/laravel-secure-bridge.svg)](https://packagist.org/packages/irfanokr/laravel-secure-bridge)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Sign — and optionally encrypt — the requests between your JavaScript front-end and your Laravel API, so they can't be tampered with, replayed, or scraped, and so payloads stay out of logs and proxies. Standard primitives only (HMAC-SHA256, AES-256-GCM). Works on **Laravel 5.5 → 12**, **PHP 7.1+**, and **any** JS front-end.

> ℹ️ This is defense-in-depth **on top of** your normal login and HTTPS — not a replacement. Before production, skim the [Threat model](#threat-model).

---

## Quick start

### 1. Install (run once)

```bash
composer require irfanokr/laravel-secure-bridge
php artisan secure-bridge:keygen          # writes SECURE_BRIDGE_KEY to your .env
```

(Laravel 5.5+ auto-discovers the package. On older versions, add `Irfanokr\SecureBridge\SecureBridgeServiceProvider` to `config/app.php`.)

### 2. Protect your routes

```php
// routes/web.php  (or routes/api.php)
Route::middleware('secure-bridge')->group(function () {
    Route::post('/profile', [ProfileController::class, 'update']);
    // ...the routes you want protected
});
```

### 3. Sign from the browser — use the block that matches your app

**A) Your front-end is the same Laravel app** (Blade pages doing `fetch` / `$.ajax`):

```bash
php artisan vendor:publish --tag=secure-bridge-assets
```
```env
SECURE_BRIDGE_SESSION_KEY=true
```
```blade
{{-- in your layout <head>, after jQuery if you use it --}}
@secureBridge
```
**Done.** Your existing `fetch` / `$.ajax` calls are now signed — you write no JavaScript.

**B) Your front-end is a separate React / Angular / Vue app with a login:**

```bash
npm install secure-bridge-client
```
```js
import SecureBridge from 'secure-bridge-client';

// run this right after your normal login returns its token:
await SecureBridge.handshake('/secure-bridge/handshake', {
  headers: { Authorization: 'Bearer ' + token },
});
SecureBridge.installFetch();   // from now on every request is signed automatically
```
Then on the server set `SECURE_BRIDGE_KEY_SOURCE=token`, turn the handshake on, and exclude your login route — the ready-to-paste server block is in **[SECURING-THE-KEY.md → Server setup](docs/SECURING-THE-KEY.md#server-setup)**.

> **That's the whole setup.** By default requests are **signed + replay-protected**. Want to also **encrypt** the body or response? Set `encrypt_request` / `encrypt_response` (see [Configuration](#configuration)).

### If a request gets rejected

| Status & code | What it means | What to do |
|---|---|---|
| `412 handshake_required` | (Option B) the browser has no key yet, or it expired | call `SecureBridge.handshake(...)`, then retry |
| `400 missing_signature` | the route is protected but the request wasn't signed | make sure `@secureBridge` / `installFetch()` actually ran |
| `400 invalid_signature` | the signature didn't match | for axios/jQuery **GET**s, put query params in the URL string, not a `params` object |
| `400 stale_timestamp` | the device clock is off by more than 5 min | sync the clock, or raise `SECURE_BRIDGE_WINDOW` |
| `409 replay` | the same signed request was sent twice | each request is single-use — don't resend it |

Run **`php artisan secure-bridge:doctor`** to check your config, or set `SECURE_BRIDGE_DEBUG=true` to log exactly why a signature failed.

Need a specific framework (Angular interceptor, axios, Vue, Svelte, Node, file uploads, downloads)? → **[docs/INTEGRATION.md](docs/INTEGRATION.md)** and **[docs/EXAMPLES.md](docs/EXAMPLES.md)**.

---

## Threat model

The honest version, because it decides whether this package is even worth adding.

**A public SPA cannot hold a secret.** Any key shipped inside downloadable JavaScript can be read by anyone who opens the bundle. So be precise about what this layer buys you.

**What it protects against (on top of HTTPS):**

| ✅ Protects | How |
|---|---|
| Request **tampering** in transit / by intermediaries | HMAC over a canonical request; any change invalidates it |
| **Replay** of a captured request | Timestamp window + single-use nonce |
| Casual **bots / scrapers** that don't run or read your JS | They can't produce a valid signature |
| **Payload exposure** in server logs, APM tools, browser extensions, TLS-terminating proxies | AES-256-GCM end-to-end between browser and PHP |

**What it does NOT *fully* stop — and how the package shrinks each gap:**

| ❌ Limitation | Why it exists | ✅ How the package reduces it |
|---|---|---|
| A **static key** in a bundle isn't secret | It's right there in the JS — anyone can read and reuse it | Don't ship a static key: use `key_source=token` (key never enters the bundle, different per session) or `session` (Blade). With `signature_driver=ecdsa` the signing key is **non-extractable** — it can't be copied out *at all*. |
| Anything **TLS already covers** | This is defense-in-depth, not a replacement for HTTPS | Keep HTTPS on (`require_https=true`); this layer *adds to* TLS. |
| **XSS on your own site** | Injected script runs with your page's privileges while the page is open | Signing can't cure XSS, but: (a) the bundled **CSP + Trusted Types** helper *prevents* most XSS; (b) `ecdsa` non-extractable keys stop the key being *stolen* for offline reuse; (c) short key TTL + a **BFF** shrink the window. Playbook → [docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md). |

**Bottom line:** it's a hardening / anti-tampering / anti-automation / log-hygiene layer — never your authentication or authorization. Keep real auth (Sanctum, Passport, JWT, sessions) underneath it.

**Pick a key source** (full guide: [docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md)):

- **`session`** — Blade per-session keys (Option A above). Never in a static bundle. Best for same-origin apps.
- **`token`** — per-session key fetched after login, kept in memory only (Option B above). Best for decoupled SPAs. Add `signature_driver=ecdsa` for a non-extractable key.
- **`static`** — key in the bundle. Only for internal tools / anti-tampering, never anything sensitive.
- **BFF** — keep the key server-side entirely; the browser holds only an HttpOnly cookie. Highest bar.

---

## Configuration

`config/secure-bridge.php` (publish it with `php artisan vendor:publish --tag=secure-bridge-config`; every value is env-overridable):

| Key | Env | Default | Purpose |
|---|---|---|---|
| `key` | `SECURE_BRIDGE_KEY` | — | Master secret (`base64:…`). Sign/enc sub-keys are HKDF-derived from it. |
| `previous_keys` | `SECURE_BRIDGE_PREVIOUS_KEYS` | `[]` | Old keys accepted during rotation. |
| `sign_requests` | `SECURE_BRIDGE_SIGN` | `true` | Verify HMAC + timestamp + nonce. |
| `encrypt_request` | `SECURE_BRIDGE_ENCRYPT_REQUEST` | `false` | Decrypt the request body. |
| `encrypt_response` | `SECURE_BRIDGE_ENCRYPT_RESPONSE` | `false` | Encrypt the response. |
| `signature_driver` | `SECURE_BRIDGE_SIGNATURE_DRIVER` | `hmac` | `hmac` or `ecdsa` (non-extractable browser keypair; needs `key_source=token`). |
| `key_source` | `SECURE_BRIDGE_KEY_SOURCE` | `static` | `static` / `session` (Blade) / `token` (SPA handshake). |
| `handshake.*` | `SECURE_BRIDGE_HANDSHAKE` | off | Per-session key endpoint for SPAs (route, auth middleware, TTL). |
| `csp.*` | `SECURE_BRIDGE_CSP` | off | Strict CSP + Trusted Types via the `secure-bridge.csp` middleware (XSS prevention). |
| `encryption_driver` | `SECURE_BRIDGE_ENCRYPTION_DRIVER` | `aes-gcm` | Swappable encryption driver. |
| `timestamp_window` | `SECURE_BRIDGE_WINDOW` | `300` | Allowed clock skew (seconds). Never `0`. |
| `replay_protection` | `SECURE_BRIDGE_REPLAY` | `true` | Enforce single-use nonces. |
| `nonce_store` | `SECURE_BRIDGE_NONCE_STORE` | `null` | Cache store for nonces (use Redis in prod / multi-server). |
| `response_mode` | `SECURE_BRIDGE_RESPONSE_MODE` | `field` | `field` (encrypt one key) or `full`. |
| `response_key` | `SECURE_BRIDGE_RESPONSE_KEY` | `data` | Field to encrypt in `field` mode. |
| `only` / `except` | — | see file | URI patterns to include/exclude (mirrors Laravel's CSRF `$except`). |
| `sign_multipart` | `SECURE_BRIDGE_SIGN_MULTIPART` | `true` | Sign `multipart/form-data` uploads body-less (so they can't bypass the layer). Body is never encrypted. |
| `require_https` | `SECURE_BRIDGE_REQUIRE_HTTPS` | `false` | Reject non-HTTPS requests (localhost exempt). |
| `session_key.enabled` | `SECURE_BRIDGE_SESSION_KEY` | `false` | Per-session keys for Blade apps (implies `key_source=session`). |
| `debug` | `SECURE_BRIDGE_DEBUG` | `false` | Log *why* a signature failed (dev only). |
| `events` | `SECURE_BRIDGE_EVENTS` | `true` | Dispatch a `RequestBlocked` event on every rejection (logging/alerting). |

### Pick features per route

Apply only what a route needs — anything not named is off:

```php
Route::middleware('secure-bridge:sign')->post('/api/login', ...);              // sign only
Route::middleware('secure-bridge:sign,encrypt-response')->get('/api/me', ...); // sign + encrypt response
Route::middleware('secure-bridge:encrypt,https')->post('/api/secret', ...);    // encrypt both + require HTTPS
Route::middleware('secure-bridge:all')->post('/api/transfer', ...);            // everything
```

Tokens: `sign`, `encrypt-request`, `encrypt-response`, `encrypt`, `all`, `https`, `no-https`. No token = use the config defaults. To register it globally instead, add `\Irfanokr\SecureBridge\Http\Middleware\SecureBridgeMiddleware::class` to the `api` middleware group and scope it with `only`/`except`.

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

`php artisan secure-bridge:doctor` prints a deterministic conformance test vector (canonical string + expected `X-Sig`), so a client developer can confirm their implementation matches the server byte-for-byte.

---

## Key rotation

```env
SECURE_BRIDGE_KEY=base64:NEWKEY...
SECURE_BRIDGE_PREVIOUS_KEYS=base64:OLDKEY...
```

New traffic uses the current key; previous keys are still **accepted** for verification/decryption, so clients update without downtime.

## Custom drivers

Bind your own and select it by name:

```php
$this->app->bind('secure-bridge.signature.ed25519', Ed25519SignatureDriver::class);
```
```env
SECURE_BRIDGE_SIGNATURE_DRIVER=ed25519
```

Implement `Irfanokr\SecureBridge\Contracts\SignatureDriver` or `EncryptionDriver`.

## Notes & limitations (by design)

- **Response encryption scope.** `field` mode (default) encrypts only the configured key (`data`); use `response_mode=full` to encrypt the whole JSON body. Streamed / binary / file responses are never encrypted.
- **Reading the decrypted body.** Controllers read decrypted fields via `$request->input()` / `all()` / `validated()`. `$request->getContent()` still returns the raw (encrypted) body.
- **Header integrity.** The signature covers method, path, query, timestamp, nonce and a body digest — not arbitrary headers. Supply a custom signature driver if you need a specific header bound in.
- **Transport.** Always run behind HTTPS (`require_https=true`); this is defense-in-depth on top of TLS, never a replacement.

---

## Requirements

- PHP **7.1+** with `ext-openssl` (AES-256-GCM) and `ext-json`.
- Laravel **5.5 → 12**.
- Browser with the Web Crypto API in a **secure context** (HTTPS or `localhost`).

## License

[MIT](LICENSE).
