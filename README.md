# Laravel Secure Bridge

[![Packagist](https://img.shields.io/packagist/v/irfanokr/laravel-secure-bridge.svg)](https://packagist.org/packages/irfanokr/laravel-secure-bridge)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Lock down the requests between your website and your Laravel server — so they can't be faked, changed, copied, or read — **without rewriting your code**. You switch it on in **one place** and it protects the requests your pages already make.

Works on **Laravel 5.5 → 12**, **PHP 7.1+**, and any front-end (Blade, React, Angular, Vue, jQuery, plain JavaScript). It's an *extra* lock on top of your normal login and HTTPS — not a replacement.

---

## How it works

Every time your website talks to your server — someone logs in, saves a form, loads a list — it sends a *request*. This package quietly does two things to each one:

1. **It signs every request.** It adds a tamper-proof "fingerprint" so your server can be sure the request really came from your site and that nobody changed it on the way. A copied request can't be re-sent later, either.
2. **It can lock the contents (optional).** Turn on encryption and the data inside the request and reply is scrambled — so even someone watching the traffic (browser tools, server logs, a company proxy) can't read it.

The important part: **you don't rewrite anything.** You switch it on in one place.

> **One honest note:** this is an *extra* lock on top of your normal login and HTTPS — not a replacement. The plain truth about what it does and doesn't stop is in ["Is this actually secure?"](#is-this-actually-secure) at the bottom.

---

## Pick your situation

There are only two ways to use this. Find yours, do that section, ignore the other.

- **A — Your pages are Laravel Blade (`.blade.php`)** — a classic Laravel website, with or without jQuery/AJAX. → **[Section A](#a--server-rendered-laravel-blade)**
- **B — Your front-end is a separate app** (React, Angular, Vue, Svelte, or plain JavaScript) that calls your Laravel API. → **[Section B](#b--separate-front-end--laravel-api)**

Not sure? If *you* write `.blade.php` files, you're **A**. If your front-end is its own project with its own `npm` build, you're **B**.

---

<a id="a--server-rendered-laravel-blade"></a>
## A — Server-rendered Laravel (Blade)

Your center point is **one line** in your layout. After you add it, every request your pages make — `fetch`, `XMLHttpRequest`, jQuery, axios — is signed automatically, for logged-in users **and** guests. You touch no JavaScript.

**1. Install (run once):**

```bash
composer require irfanokr/laravel-secure-bridge
php artisan secure-bridge:keygen                       # creates your secret key
php artisan vendor:publish --tag=secure-bridge-assets  # adds the browser script
```

**2. Turn it on — one line in `.env`:**

```env
SECURE_BRIDGE_SESSION_KEY=true
```

**3. Add the one line — `@secureBridge` in your layout's `<head>`:**

This is the Blade file with your `<html>`/`<head>`/`<body>`, usually `resources/views/layouts/app.blade.php`. Put `@secureBridge` just before `</head>`:

```blade
<head>
    <title>My App</title>

    @secureBridge   {{-- 👈 the one line you add, just before </head> --}}
</head>
```

That single tag switches everything on. (Using jQuery? Keep your jQuery `<script>` line **above** `@secureBridge`.) No shared layout? Add the line to each page that talks to the server.

**4. Protect the routes you want signed** in `routes/web.php`. Put them *inside* the group; anything **outside keeps working exactly as before**:

```php
// Protected — requests to these must be signed:
Route::middleware('secure-bridge')->group(function () {
    Route::post('/profile', [ProfileController::class, 'update']);
    Route::get('/orders', [OrderController::class, 'list']);
});

// Not protected — works normally, no signing needed:
Route::get('/', [HomeController::class, 'index']);
```

### You're done.

Every request your Blade pages already make is now signed. You changed one line and wrote zero JavaScript. (Login / register / forgot-password forms are signed too, even before login — the key lives in the guest session and carries over once they log in.)

### How to check it worked

1. Run **`php artisan secure-bridge:doctor`**. If it lists your key and a `signature_driver`, the server side is ready. ✅
2. In your browser open **DevTools → Network**, trigger a request, click it, and look at **Request Headers** for **`X-Sig`** (plus `X-Timestamp`, `X-Nonce`). Seeing it means it's signed. ✅
3. On `localhost` nothing else is needed. In production, serve over **HTTPS**.

---

<a id="b--separate-front-end--laravel-api"></a>
## B — Separate front-end + Laravel API

Here Laravel is just the API and your front-end (React, Angular, Vue, Svelte, plain JS) is a separate project. Your center point is **one call** at app startup. You add it **once**; it quietly gets a signing key on the first request, keeps it fresh, and signs every request after that — for `fetch`, axios, jQuery and Angular `HttpClient` alike. You never touch your request code, your login code, or anything about page reloads.

**1. Server — install (run once):**

```bash
composer require irfanokr/laravel-secure-bridge
php artisan secure-bridge:keygen      # creates your secret key
```

**2. Server — turn it on in `.env`:**

```env
SECURE_BRIDGE_KEY_SOURCE=token
SECURE_BRIDGE_HANDSHAKE=true
```

**3. Server — point the key handshake at your login guard.** Publish the config and set your guard in one place:

```bash
php artisan vendor:publish --tag=secure-bridge-config
```
```php
// config/secure-bridge.php
'handshake' => [
    'enabled'    => true,
    'route'      => 'secure-bridge/handshake',
    'middleware' => ['auth:sanctum'],   // 👈 YOUR login guard (auth:api / jwt.auth / passport …)
],
'except' => ['api/login', 'api/register', 'secure-bridge/handshake'],
```

**4. Server — protect the routes you want signed** in `routes/api.php`. Keep your **login** route out of the group (it has no key yet); anything outside keeps working normally:

```php
Route::middleware('secure-bridge')->group(function () {
    // your protected API routes go here
});
```

**5. Front-end — install the client (run once):**

```bash
npm install secure-bridge-client
```

**6. Front-end — the one call, at app startup.** Put this **once**, where your app boots (`main.js` / `index.js` / your root component / Angular `APP_INITIALIZER`). Point `token` at wherever your app keeps its normal login token:

```js
import SecureBridge from 'secure-bridge-client';

SecureBridge.start({
  handshake: '/secure-bridge/handshake',
  token: () => localStorage.getItem('auth_token'),   // 👈 however YOUR app stores its login token
});
```

That's the whole integration. It hooks `fetch` and `XMLHttpRequest` — which axios, jQuery and Angular `HttpClient` all use underneath — so every request is signed with no per-call changes.

### You're done.

You added one call in one place. There is **nothing** to wire into your login flow, **nothing** to wire for page reloads, and **no** `412` error to handle yourself: the client gets the key on the first request that has a token, refreshes it before it expires, and re-gets it automatically if your login token changes. A request made before login (no token yet) is simply sent unsigned, so your public and login routes keep working.

> **Works with any auth — JWT, Sanctum, Passport, sessions.** Put **your** guard in `handshake.middleware`. The signing key is bound to the bearer token your app already sends, so each request carries both your `Authorization: Bearer …` (checked by *your* auth) **and** the `X-Sig` signature (checked by this package) — two independent layers; order doesn't matter.

### How to check it worked

1. Run **`php artisan secure-bridge:doctor`** on the server — it should list your key and `signature_driver`. ✅
2. Log in, then in **DevTools → Network** click any request to a protected route and look at **Request Headers** for **`X-Sig`** (plus `X-Timestamp`, `X-Nonce`). ✅
3. You'll also see one request to `/secure-bridge/handshake` the first time — that's the client fetching its key. That's expected.

> **Where exactly does the one call go in my framework** (React / Angular / Vue / Svelte / plain JS / jQuery / Node)? See **[docs/INTEGRATION.md](docs/INTEGRATION.md)**.

---

## Advanced (only if you need it)

Section A or B above already works. Open this only for extra options.

<details>
<summary><b>Advanced options &amp; full reference</b></summary>

- **Where the one call goes in your framework**, the manual `handshake()` + `install()` pattern, response decryption, file uploads, the signed-GET query gotcha, the **full configuration table**, the **refusal-code list**, and the **glossary** → **[docs/INTEGRATION.md](docs/INTEGRATION.md)**
- **How safe is this, where the key lives, XSS, non-stealable keys, the BFF pattern** → **[docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md)**
- **Also encrypt the data** (not just sign it): set `SECURE_BRIDGE_ENCRYPT_REQUEST=true` and/or `SECURE_BRIDGE_ENCRYPT_RESPONSE=true`. The package unscrambles automatically; your controllers still read normal data.
- **Per-route features**: `secure-bridge:sign`, `secure-bridge:sign,encrypt-response`, `secure-bridge:encrypt,https`, `secure-bridge:all` (full list in INTEGRATION.md).
- **Change the key later (rotation)**: set `SECURE_BRIDGE_KEY` (new) and `SECURE_BRIDGE_PREVIOUS_KEYS` (old); old requests keep working during the switch.
- **Log/alert when a request is blocked**: listen for `Irfanokr\SecureBridge\Events\RequestBlocked` (metadata only, never the payload).

</details>

---

<a id="is-this-actually-secure"></a>
## Is this actually secure?

The honest answer, in plain words.

**What it genuinely protects:**

- Nobody can **change** a request without the server noticing.
- A captured request can't be **re-sent** later.
- Simple **bots and scrapers** that don't run your site's code can't make valid requests.
- With encryption on, the data is **hidden** from logs, browser extensions, and company proxies.

**What it does *not* do (and how the package helps anyway):**

- **A key inside public JavaScript is not a real secret.** So for separate apps the key is fetched after login and kept in memory only (never in your downloadable code); for Blade sites it lives in the per-session key. With the `ecdsa` option the key can't even be copied out.
- **It is not a replacement for HTTPS or for your login.** It's an extra layer on top. Keep both.
- **It can't protect a page that's already running an attacker's script (XSS).** Nothing signing-based can. The package ships an anti-XSS helper (CSP + Trusted Types) to *prevent* that, and non-stealable keys to limit the damage if it happens.

The full, careful version is in **[docs/SECURING-THE-KEY.md](docs/SECURING-THE-KEY.md)**.

---

## Requirements

- PHP **7.1+** with the `openssl` and `json` extensions.
- Laravel **5.5 → 12**.
- A browser on **HTTPS** (or `localhost`).

## License

[MIT](LICENSE).
