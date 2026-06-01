# Laravel Secure Bridge

[![Packagist](https://img.shields.io/packagist/v/irfanokr/laravel-secure-bridge.svg)](https://packagist.org/packages/irfanokr/laravel-secure-bridge)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A simple way to lock down the requests between your website and your Laravel server — so they can't be faked, changed, copied, or read — **without rewriting your code**.

Works on **Laravel 5.5 → 12**, **PHP 7.1+**, and any front-end (Blade, React, Angular, Vue, jQuery…).

---

## How it works

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

**4. Choose which routes to protect** in `routes/web.php`. Put the routes whose requests you want signed *inside* the group; anything **outside keeps working exactly as before** (no signing needed):

```php
// Protected — requests to these must be signed:
Route::middleware('secure-bridge')->group(function () {
    Route::post('/profile', [ProfileController::class, 'update']);
    Route::get('/orders', [OrderController::class, 'list']);
});

// Not protected — works normally:
Route::get('/', [HomeController::class, 'index']);
```

**Done.** Every request your Blade pages already make — `fetch`, jQuery, axios, `XMLHttpRequest` — is now signed automatically. You did not change any JavaScript.

#### A complete example page (copy-paste)

```blade
{{-- resources/views/layouts/app.blade.php --}}
<!DOCTYPE html>
<html>
<head>
    <title>My App</title>
    @secureBridge   {{-- the one line you add --}}
</head>
<body>
    <button onclick="saveName()">Save</button>
    <script>
      async function saveName() {
        // ordinary fetch — already signed; you write nothing special:
        const res = await fetch('/profile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Ali' }),
        });
        console.log(await res.json());
      }
    </script>
</body>
</html>
```

#### Did it work?

1. Run **`php artisan secure-bridge:doctor`** — it prints your settings and a sample signature. If it lists your key and `signature_driver`, the server side is ready.
2. In the browser, open **DevTools → Network**, trigger a request, click it, and look at its **Request Headers**. You should see **`X-Sig`**, **`X-Timestamp`** and **`X-Nonce`** — that means it's signed. ✅
3. On `localhost` you need nothing extra. In production, serve over **HTTPS** (and you can enforce it with `SECURE_BRIDGE_REQUIRE_HTTPS=true`).

#### What about login / forgot-password / register (before the user is logged in)?

These AJAX forms work too — and you don't need a token. In Blade mode the signing key lives in the Laravel **session**, which exists for **guests** as well. As long as those pages render `@secureBridge` (use your shared layout, or add the line to each view), their `POST`s are signed with the guest-session key and verified the same way. After a successful login Laravel regenerates the session id and the key **carries over**, so your authenticated requests keep working. Two notes:

- In this mode apply `secure-bridge` to **web routes** (they have a session), not `api` routes; it runs after Laravel's session middleware automatically.
- This is *in addition to* Laravel's CSRF protection, not a replacement. (Prefer not to sign pre-login routes? Add them to the `except` list instead.)

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

Protect your API routes in `routes/api.php` — keep your **login** route out of the group (it has no key yet):

```php
Route::middleware('secure-bridge')->group(function () {
    // your protected API routes go here
});
```

Then publish the config and set, in **one place**, which guard protects the handshake and which routes to skip:

```bash
php artisan vendor:publish --tag=secure-bridge-config
```
```php
// config/secure-bridge.php
'handshake' => [
    'enabled'    => true,
    'route'      => 'secure-bridge/handshake',
    'middleware' => ['auth:sanctum'],   // 👈 YOUR login guard
],
'except' => ['api/login', 'api/register', 'secure-bridge/handshake'],
```

> **Works with any auth — JWT, Sanctum, Passport, sessions.** Put **your** guard in `handshake.middleware` — `auth:sanctum`, `auth:api` (JWT), `jwt.auth` (tymon/jwt-auth), Passport, etc. The signing key is bound to the **bearer token** the client sends, so after login every request carries both your `Authorization: Bearer …` (checked by *your* auth) **and** the `X-Sig` signature (checked by this package) — two independent layers that compose; middleware order doesn't matter. If your token is **refreshed/rotated** (common with JWT), the next request returns `412 handshake_required` — just re-handshake with the new token and retry.

#### Step 2 — your front-end (any framework)

Install the client once:

```bash
npm install secure-bridge-client
```

Then, **whenever your app has a logged-in user, do two things** — once at login, and again on every page load:

```js
import SecureBridge from 'secure-bridge-client';

async function startSecureBridge(token) {        // `token` = your app's normal login token
  // 1. Ask the server for this session's signing key (the "handshake"):
  await SecureBridge.handshake('/secure-bridge/handshake', {
    headers: { Authorization: 'Bearer ' + token },
  });
  // 2. Turn on signing for EVERY request your app makes:
  SecureBridge.install();
}
```

That single `SecureBridge.install()` is the whole point. It hooks the browser's request machinery (`fetch` **and** `XMLHttpRequest`). **It does not matter how your app sends requests** — `fetch`, `axios`, `jQuery`, and even **Angular's `HttpClient`** all run on top of those two, so every one of them is signed automatically. **You never touch your request code** — there is nothing to change across your screens, no matter how many requests you have.

> **You change exactly ONE place — never your request files.** You add this package's code only at your app's startup (the two lines above). You do **not** edit, wrap, or replace any `fetch`/`$.ajax`/`$http`/axios call anywhere — not one, whether you have 10 requests or 10,000.
>
> This is also why you don't need jQuery's `ajaxPrefilter` / `ajaxStart` / `beforeSend`: those only catch jQuery's own calls. `install()` hooks `fetch` and `XMLHttpRequest` — the layer that jQuery, axios and Angular all use underneath — so it catches **everything** with one call. (See [Exactly which requests get signed?](#which-requests) for the full list.)

> ### ⚠️ Important: page reloads — read this
> The signing key is kept in **memory only** (a JavaScript variable). The package **never** puts it in `localStorage`, `sessionStorage`, or a cookie, because anything there can be read by any script (XSS) and lingers after the session — that would defeat the security.
>
> So a **page reload wipes the key.** What survives a reload is *your own login token* (the cookie or storage your app already uses for auth) — **not** anything from this package. The fix is simple: **call `startSecureBridge(token)` at app startup too**, not only on the login click. A reload just re-runs it and gets a fresh key. If a request fires before that finishes, the server replies **`412 handshake_required`** — catch it, call `handshake()` again, and retry.
>
> (This only applies to the separate-app `token` mode. The Blade setup (A) doesn't have it — the server injects a fresh key into every page render — and `static` mode keeps the key in the code.)

**Where do those calls go?** Complete copy-paste code for each framework — including the on-reload wiring and the `412` retry — is in **[docs/INTEGRATION.md](docs/INTEGRATION.md)**. In short:

- **React / Vue / Svelte:** call `startSecureBridge(token)` in your login handler **and** in your app's bootstrap/root effect that runs on load (when a saved token exists).
- **Angular:** the same — in your auth service after login, and in an `APP_INITIALIZER` (or your root component) on startup. `install()` covers `HttpClient` by itself; you do **not** need an Angular interceptor.
- **Plain HTML, no build tools:** load the client with one tag, then run it both after login and on page load:

  ```html
  <script src="https://unpkg.com/secure-bridge-client"></script>
  <script>
    async function startSecureBridge(token) {
      await SecureBridge.handshake('/secure-bridge/handshake', { headers: { Authorization: 'Bearer ' + token } });
      SecureBridge.install();   // every fetch / XHR from now on is signed
    }

    async function login(email, password) {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const { token } = await res.json();
      localStorage.setItem('auth_token', token);   // YOUR login token persists (your choice)
      await startSecureBridge(token);
    }

    // On every page load, if already logged in, re-fetch a fresh key:
    window.addEventListener('load', function () {
      const token = localStorage.getItem('auth_token');
      if (token) { startSecureBridge(token); }
    });
  </script>
  ```

> **Only if you turn on response encryption** (`encrypt_response`): decrypted replies are applied automatically for `fetch`; for `XMLHttpRequest`-based requests (axios / jQuery / Angular) call `SecureBridge.processResponse(reply)` in your handler. Plain signing always works everywhere with nothing extra.

---

## Advanced (only if you need it)

Everything here is **optional** — Setup A or B above already works. Open the part you need.

<a id="which-requests"></a>
<details>
<summary><b>Exactly which requests get signed? (does it really catch everything?)</b></summary>

`install()` hooks the browser's two request engines — `fetch` and `XMLHttpRequest` — so it catches every request **regardless of the library**, because they all use one of those two underneath. You wire it once at startup; you never touch a single call site.

**Signed automatically (✅):**

| How your code sends the request | What it uses underneath | Signed? |
|---|---|---|
| `fetch(...)` | `fetch` | ✅ |
| `new XMLHttpRequest()` (raw) | `XMLHttpRequest` | ✅ |
| jQuery `$.ajax` / `$.get` / `$.post` / `$.getJSON` / `$(...).load()` | `XMLHttpRequest` | ✅ |
| axios (browser) | `XMLHttpRequest` | ✅ |
| Angular `HttpClient` (`this.http.get/post/...`) | `XMLHttpRequest` (or `fetch` with `withFetch()`) | ✅ |
| anything built on the above (react-query, SWR, Vue Resource, …) | `fetch` / `XMLHttpRequest` | ✅ |

**Not signed (rare, and none are normal API calls) (❌):**

| Mechanism | Why | What to do if you need it |
|---|---|---|
| `navigator.sendBeacon()` | Fire-and-forget telemetry on page unload; not a normal request | Use `SecureBridge.signUrl()` and beacon to a signed URL, if it matters |
| **JSONP** (`<script>`-tag, e.g. Angular `HttpClient.jsonp`) | It's a script include, not a request with headers/body | JSONP is cross-origin and legacy; avoid for protected endpoints |
| WebSocket / Server-Sent Events | A different protocol, not HTTP request/response | Authenticate the socket separately |
| A native `<form>` submit (full page navigation) | The browser navigates; it's not an AJAX call | For a signed download link use `SecureBridge.signUrl()` |

So: every way your app makes **API/data requests** is covered by the one `install()` call. The exceptions are things that aren't AJAX in the first place.
</details>

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
| `412 handshake_required` | (separate-app setup) the browser hasn't got its key yet, or it expired — often right after a **page reload** | call `SecureBridge.handshake(...)` again, then retry the request |
| `400 missing_signature` | the route is protected but the request wasn't signed | make sure `@secureBridge` (Blade) or `SecureBridge.install()` (separate app) actually ran before the request |
| `400 invalid_signature` | the fingerprint didn't match | for jQuery/axios **GET**s, put the query values in the URL, not a separate `data`/`params` object |
| `400 stale_timestamp` | the device clock is more than 5 minutes off | fix the clock, or raise `SECURE_BRIDGE_WINDOW` |
| `409 replay` | the same signed request was sent twice | each request can only be used once — don't resend the identical one |
| handshake route returns `401`/`404` | the handshake endpoint isn't reachable or your guard rejected it | confirm `SECURE_BRIDGE_HANDSHAKE=true`, the `handshake.middleware` guard matches your login, and the route isn't blocked |

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

<details>
<summary><b>Log or alert when a request is blocked (observability)</b></summary>

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
</details>

<details>
<summary><b>Glossary — the words in this README, in plain English</b></summary>

| Word | Plain meaning |
|---|---|
| **Signature / "fingerprint"** | A short code attached to each request (the `X-Sig` header) that the server recomputes to check the request is genuine and unchanged. |
| **Sign a request** | Attach that fingerprint so the server will accept it. |
| **Handshake** | One request your app makes after login to get its signing key from the server. |
| **Per-session key** | A signing key that's different for every logged-in session and is thrown away when the session ends. |
| **Nonce** | A random value used once per request, so a captured request can't be replayed later. |
| **Timestamp window** | How far the device clock may differ from the server (default 5 min) before a request is rejected. |
| **Canonical string** | The exact text (method + path + query + timestamp + nonce + body) that both sides build identically to compute/verify the signature. |
| **HMAC** | The normal signing method — one shared key signs and verifies. |
| **ECDSA (non-extractable key)** | A stronger option: the browser holds a key it can *use* but JavaScript can never read or copy out (so even malicious script can't steal it). |
| **Encryption (AES-256-GCM)** | Optional scrambling of the request/response contents so onlookers (logs, proxies, extensions) can't read them. |
| **`install()`** | The one client call that turns on signing for every request your app makes. |
| **BFF (Backend-for-Frontend)** | An optional small server between your browser and API so the key never lives in the browser at all — the highest-security setup. |
| **Multipart (signed "body-less")** | File uploads are still signed, but the file bytes themselves aren't part of the signature (the browser controls that format). |
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
