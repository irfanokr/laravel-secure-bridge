# Laravel Secure Bridge

[![Packagist](https://img.shields.io/packagist/v/irfanokr/laravel-secure-bridge.svg)](https://packagist.org/packages/irfanokr/laravel-secure-bridge)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A simple way to lock down the requests between your website and your Laravel server — so they can't be faked, changed, copied, or read — **without rewriting your code**.

Works on **Laravel 5.5 → 12**, **PHP 7.1+**, and any front-end (Blade, React, Angular, Vue, jQuery…).

---

## How it works (in plain words)

Every time your website talks to your server — someone logs in, saves a form, loads a list — it sends a *request*. Normally those requests travel in the open. This package quietly does two things to each one:

1. **It signs every request.** It adds a tamper-proof "fingerprint" so your server can be sure the request really came from your website and that nobody changed it on the way. If anything was touched, the server refuses it. It also stops someone from copying a request and sending it again later.

2. **It can lock the contents (optional).** If you turn on encryption, the data inside the request and the reply is scrambled — so even someone watching the traffic (browser tools, server logs, a company proxy) can't read it.

The important part: **you don't rewrite anything.** You switch it on in one place, and it protects the requests your pages already make.

> **One honest note:** this is an *extra* lock on top of your normal login and HTTPS — not a replacement. Keep using your usual login (Sanctum, Passport, JWT, sessions). The plain truth about what it does and doesn't stop is in ["Is this actually secure?"](#is-this-actually-secure) at the bottom.

---

## Setup

**First, what kind of front-end do you have?** Pick the one that matches your project — the steps are different.

- **A — Laravel Blade pages.** Your screens are `.blade.php` files rendered by Laravel (the classic Laravel website). → **[Setup A](#setup-a)** below.
- **B — A separate front-end app.** React, Angular, Vue, Svelte, or plain JavaScript that calls your Laravel API. → **[Setup B](#setup-b)** below.

Not sure? If you write `.blade.php` files, you're **A**. If your front-end is a separate project (its own `npm` build) that talks to Laravel over an API, you're **B**.

---

<a id="setup-a"></a>
### Setup A — Laravel Blade pages

For a classic Laravel website whose pages are Blade files using `fetch` or jQuery.

**1. Install it.** Run these three commands once:

```bash
composer require irfanokr/laravel-secure-bridge
php artisan secure-bridge:keygen                       # creates your secret key
php artisan vendor:publish --tag=secure-bridge-assets  # adds the browser script
```

**2. Turn it on.** Add one line to your `.env` file:

```env
SECURE_BRIDGE_SESSION_KEY=true
```

**3. Add one line to the layout your pages share.**

This is the Blade file that has your `<html>`, `<head>` and `<body>` — usually `resources/views/layouts/app.blade.php`. Open it and put `@secureBridge` just before the closing `</head>`:

```blade
<head>
    <title>My App</title>

    @secureBridge   {{-- 👈 add this one line, just before </head> --}}
</head>
```

`@secureBridge` is a Blade tag — Laravel turns it into the small script that switches everything on, so it must be on a page (the `<head>` of your shared layout is the easy place; if you don't have a shared layout, add it to each page that talks to the server).

*Using jQuery?* Just make sure your jQuery `<script>` line sits **above** `@secureBridge`.

**4. Choose what to protect** in `routes/web.php`:

```php
Route::middleware('secure-bridge')->group(function () {
    // put the routes you want protected inside here
});
```

**Done.** Every `fetch` and jQuery request your pages already make is now signed automatically. You did not change any JavaScript.

To confirm it's working, run **`php artisan secure-bridge:doctor`**.

---

<a id="setup-b"></a>
### Setup B — A separate front-end app (React / Angular / Vue / plain JS)

Here your screens are **not** Blade — Laravel is just the API, and your front-end (React, Angular, Vue, or plain JavaScript) is a separate project.

**How it works, in plain words:** you don't want your secret key sitting inside downloadable JavaScript, because anyone could read it there. So instead, **right after a user logs in, your app asks the server once for a key.** That one request is called the *handshake*. The server gives that logged-in session its own key, your app keeps it in memory, and from then on every request is signed with it. You add this in **one place** — you never touch your other request code.

#### Step 1 — the server (same for every front-end)

```bash
composer require irfanokr/laravel-secure-bridge
php artisan secure-bridge:keygen      # creates your secret key
```

In `.env`, turn on "give the browser a key after login":

```env
SECURE_BRIDGE_KEY_SOURCE=token
SECURE_BRIDGE_HANDSHAKE=true
```

Protect your API routes in `routes/api.php`, but leave your **login** route out of the group (it has no key yet):

```php
Route::middleware('secure-bridge')->group(function () {
    // your protected API routes go here
});
```

(The small handshake config — which login guard protects it, which routes to skip — is in [docs/SECURING-THE-KEY.md → Server setup](docs/SECURING-THE-KEY.md#server-setup).)

#### Step 2 — your front-end: open the box for the app you use

Each box is a **complete** example that shows exactly where the code goes. You only ever do three things: install once, call the handshake once after login, and add one "switch it on" line. Your existing requests are never rewritten.

<details>
<summary><b>Plain JavaScript / HTML (no build tools, no npm)</b></summary>

```html
<!-- 1. Load the client — one script tag in your page. -->
<script src="https://unpkg.com/secure-bridge-client"></script>

<script>
  // 2. Your normal login, then the handshake, then switch signing on.
  async function login() {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'me@example.com', password: 'secret' }),
    });
    const data = await res.json();

    // Ask the server once for this session's key:
    await SecureBridge.handshake('/secure-bridge/handshake', {
      headers: { Authorization: 'Bearer ' + data.token },
    });

    // Switch signing on. After this, write normal fetch() anywhere — it's signed.
    SecureBridge.installFetch();
  }

  // Anywhere later in your code — unchanged, now automatically signed:
  // fetch('/api/orders', { method: 'POST', body: JSON.stringify({ item: 42 }) });
</script>
```
</details>

<details>
<summary><b>React</b></summary>

```jsx
// 1. Install once:  npm install secure-bridge-client
import SecureBridge from 'secure-bridge-client';

// 2. In the function that runs after a successful login:
async function onLoginSuccess(token) {
  await SecureBridge.handshake('/secure-bridge/handshake', {
    headers: { Authorization: 'Bearer ' + token },
  });
  SecureBridge.installFetch();          // or: SecureBridge.installAxios(axios)
}

// 3. Done. Every fetch()/axios call in your app is now signed.
//    You do NOT change your existing requests.
```
</details>

<details>
<summary><b>Angular</b></summary>

Angular has a built-in way to touch every request — an "interceptor". You write this one file and never edit your `this.http.get/post(...)` calls.

```ts
// 1. Install once:  npm install secure-bridge-client

// 2. Create this file:  src/app/secure-bridge.interceptor.ts
import { HttpInterceptorFn } from '@angular/common/http';
import { from, switchMap } from 'rxjs';
import SecureBridge from 'secure-bridge-client';

export const secureBridgeInterceptor: HttpInterceptorFn = (req, next) =>
  from(SecureBridge.prepare(req.method, req.urlWithParams, req.body)).pipe(
    switchMap(p => next(req.clone({ setHeaders: p.headers, body: p.body ?? req.body })))
  );

// 3. Register it once, in main.ts:
import { provideHttpClient, withInterceptors } from '@angular/common/http';
bootstrapApplication(AppComponent, {
  providers: [provideHttpClient(withInterceptors([secureBridgeInterceptor]))],
});

// 4. After your login returns a token, do the handshake once:
await SecureBridge.handshake('/secure-bridge/handshake', {
  headers: { Authorization: 'Bearer ' + token },
});
// From now on every this.http.get/post(...) is signed. Nothing else changes.
```

(On an older Angular that uses `NgModule`? The class-based interceptor version is in [docs/INTEGRATION.md → Angular](docs/INTEGRATION.md#angular).)
</details>

<details>
<summary><b>Vue</b></summary>

```js
// 1. Install once:  npm install secure-bridge-client
import SecureBridge from 'secure-bridge-client';
import axios from 'axios';   // if you use axios

// 2. After a successful login:
async function onLoginSuccess(token) {
  await SecureBridge.handshake('/secure-bridge/handshake', {
    headers: { Authorization: 'Bearer ' + token },
  });
  SecureBridge.installAxios(axios);     // or SecureBridge.installFetch() if you use fetch
}

// 3. Done. Every request your app makes is now signed — you change nothing else.
```
</details>

---

## Advanced (only if you need it)

Everything here is **optional** — Setup A or B above already works. Open the part you need.

<details>
<summary><b>Also scramble (encrypt) the data, not just sign it</b></summary>

By default requests are signed but not scrambled. To also encrypt the contents, add to `.env`:

```env
SECURE_BRIDGE_ENCRYPT_REQUEST=true     # scramble what the browser sends
SECURE_BRIDGE_ENCRYPT_RESPONSE=true    # scramble what the server sends back
```

The package unscrambles it automatically on each side. Your controllers still read normal data with `$request->input(...)`, and your JavaScript still gets normal data back.
</details>

<details>
<summary><b>Protect only some routes, or pick features per route</b></summary>

Apply the middleware only where you want it, and choose which features run on each route (anything you don't name is off):

```php
Route::middleware('secure-bridge:sign')->post('/api/login', ...);              // sign only
Route::middleware('secure-bridge:sign,encrypt-response')->get('/api/me', ...); // sign + scramble the reply
Route::middleware('secure-bridge:encrypt,https')->post('/api/secret', ...);    // scramble both ways + force HTTPS
Route::middleware('secure-bridge:all')->post('/api/transfer', ...);            // everything
```

Words you can use: `sign`, `encrypt-request`, `encrypt-response`, `encrypt`, `all`, `https`, `no-https`. With no word it uses your normal settings.
</details>

<details>
<summary><b>Stronger security (non-stealable keys, anti-XSS, server-only key)</b></summary>

For higher-value apps the package supports:

- **Non-extractable keys** (`SECURE_BRIDGE_SIGNATURE_DRIVER=ecdsa`, with the token setup above) — the browser's signing key can't be copied out, even by malicious scripts.
- **A built-in CSP + Trusted Types helper** to *prevent* cross-site-scripting in the first place.
- **A "BFF" pattern** where the key never leaves the server at all.

These are explained simply, with when-to-use-each, in **[docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md)**.
</details>

<details>
<summary><b>Change the key later (rotation)</b></summary>

```env
SECURE_BRIDGE_KEY=base64:NEW_KEY...
SECURE_BRIDGE_PREVIOUS_KEYS=base64:OLD_KEY...
```

New requests use the new key; the old key still works for a while, so your users don't get logged out or broken during the switch.
</details>

<details>
<summary><b>All settings (full configuration reference)</b></summary>

Publish the config file with `php artisan vendor:publish --tag=secure-bridge-config`. Every value can also be set in `.env`.

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
</details>

<details>
<summary><b>If a request gets refused — what the codes mean</b></summary>

| Code you see | What it means | What to do |
|---|---|---|
| `412 handshake_required` | (separate-app setup) the browser hasn't got its key yet, or it expired | call `SecureBridge.handshake(...)` again, then retry |
| `400 missing_signature` | the route is protected but the request wasn't signed | make sure `@secureBridge` (or `installFetch()`) actually ran |
| `400 invalid_signature` | the fingerprint didn't match | for jQuery/axios **GET**s, put the query values in the URL, not a separate `data`/`params` object |
| `400 stale_timestamp` | the device clock is more than 5 minutes off | fix the clock, or raise `SECURE_BRIDGE_WINDOW` |
| `409 replay` | the same request was sent twice | each request can only be used once — don't resend it |

Tip: set `SECURE_BRIDGE_DEBUG=true` while developing and the log tells you exactly what went wrong.
</details>

<details>
<summary><b>Technical details (for the curious): what's on the wire, custom drivers</b></summary>

The fingerprint is an HMAC-SHA256 over a canonical string, and encryption is AES-256-GCM (standard, audited building blocks — nothing hand-rolled):

```
canonical = METHOD \n PATH \n QUERY \n TIMESTAMP \n NONCE \n sha256hex(body)
header    X-Sig: v1=<hmac_sha256_hex(signKey, canonical)>
          X-Timestamp, X-Nonce   (or __sb_sig / __sb_ts / __sb_nonce for download links)
envelope  v1.<base64(iv)>.<base64(ciphertext+tag)>   (AES-256-GCM, AAD "secure-bridge:v1")
```

`php artisan secure-bridge:doctor` prints a sample fingerprint so a client developer can confirm both sides agree.

You can swap in your own signing or encryption method by binding a driver:

```php
$this->app->bind('secure-bridge.signature.ed25519', Ed25519SignatureDriver::class);
```
```env
SECURE_BRIDGE_SIGNATURE_DRIVER=ed25519
```

Implement `Irfanokr\SecureBridge\Contracts\SignatureDriver` or `EncryptionDriver`.
</details>

---

<a id="threat-model"></a>
## Is this actually secure?

The honest answer, in plain words.

**What it genuinely protects:**

- Nobody can **change** a request without the server noticing.
- A captured request can't be **re-sent** later.
- Simple **bots and scrapers** that don't run your site's code can't make valid requests.
- With encryption on, the data is **hidden** from logs, browser extensions, and company proxies.

**What it does *not* do (and how the package helps anyway):**

- **A key inside public JavaScript is not a real secret.** Anyone can read your downloadable code. → So for separate apps, use the "give the browser a key after login" setup (the key never sits in your code) or, for Blade sites, the per-session key from the simple setup above. With the `ecdsa` option the key can't even be copied out.
- **It is not a replacement for HTTPS or for your login.** It's an extra layer on top. Keep both.
- **It can't protect a page that's already running an attacker's script (XSS).** Nothing signing-based can. The package ships an anti-XSS helper (CSP + Trusted Types) to *prevent* that, and non-stealable keys to limit the damage if it happens.

The full, careful version (with the strongest setups) is in **[docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md)**.

---

## Requirements

- PHP **7.1+** with the `openssl` and `json` extensions.
- Laravel **5.5 → 12**.
- A browser on **HTTPS** (or `localhost`).

## License

[MIT](LICENSE).
