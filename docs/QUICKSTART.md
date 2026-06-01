# 5-minute beginner guide

No security or cryptography knowledge needed. Follow the steps for your situation and it works.

---

## 1. What does this package actually do?

It sits between your **website's front-end** (the JavaScript that runs in the browser) and your **Laravel back-end**. For every request it can:

- **Sign** it — so the server can tell the request really came from your app and wasn't tampered with on the way.
- **Encrypt** it — so the data is scrambled and unreadable in browser tools, logs, and proxies (on top of HTTPS).
- **Block replays** — so a captured request can't be re-sent later by someone else.

You turn each of these on or off. You don't have to understand the cryptography — the package does it for you.

> ⚠️ One honest thing to know up front: this is **extra protection on top of** your normal login (Sanctum/Passport/JWT/sessions) and HTTPS. It does **not** replace them. Keep your normal login as-is.

---

## 2. Which one are you? (pick a row)

| Your situation | What to use | Jump to |
|---|---|---|
| My front-end and Laravel are the **same project** (Blade views, `.blade.php` pages, jQuery/`fetch` AJAX) | **Session mode** — the server handles everything for you | [Setup A](#setup-a--blade-app-easiest) |
| My front-end is a **separate** React / Angular / Vue app that talks to a Laravel API, and users **log in** | **Token mode** — the safest option for separate apps | [Setup B](#setup-b--separate-reactangularvue-app) |
| Just a small internal tool / I only want to stop casual tampering, no login | **Static mode** — quickest, least secure | [Setup C](#setup-c--quick-and-simple-internal-tools) |

If you're not sure, you're almost certainly **Setup A** (same project) or **Setup B** (separate app).

---

## 3. One-time install (everyone does this)

On your Laravel server, run these three commands:

```bash
composer require irfanokr/laravel-secure-bridge
php artisan secure-bridge:keygen          # creates a secret key in your .env
php artisan vendor:publish --tag=secure-bridge-config
```

That's the whole server install. Now pick your setup below.

---

## Setup A — Blade app (easiest)

**Your front-end and Laravel are the same project.** The server does all the work; you write almost no JavaScript.

### Step 1 — turn on session mode

In your `.env` file:

```env
SECURE_BRIDGE_KEY_SOURCE=session
SECURE_BRIDGE_SESSION_KEY=true
```

### Step 2 — publish the browser script once

```bash
php artisan vendor:publish --tag=secure-bridge-assets
```

### Step 3 — add one line to your layout

In your main Blade layout, inside `<head>` (and **after** jQuery if you use jQuery):

```blade
@secureBridge
```

### Step 4 — protect your routes

In `routes/web.php` (or `api.php`), wrap the routes you want protected:

```php
Route::middleware('secure-bridge')->group(function () {
    Route::post('/profile/update', [ProfileController::class, 'update']);
    // ...your other routes
});
```

**Done.** Your existing `fetch()` and `$.ajax` calls are now automatically signed. You changed no JavaScript. The secret key is generated fresh for each visitor's session and is never written into a file the public can download.

---

## Setup B — separate React/Angular/Vue app

**Your front-end is a separate app and users log in.** The server hands the browser a private key *after* login, so no key is ever buried in your downloadable JavaScript.

### Step 1 — turn on token mode

In your Laravel `.env`:

```env
SECURE_BRIDGE_KEY_SOURCE=token
SECURE_BRIDGE_HANDSHAKE=true
SECURE_BRIDGE_SIGNATURE_DRIVER=ecdsa     # safest setting; leave it on
```

In `config/secure-bridge.php`, tell it which routes have **no key yet** (login/register/the handshake itself), so they aren't required to be signed:

```php
'handshake' => [
    'enabled'    => true,
    'route'      => 'secure-bridge/handshake',
    'middleware' => ['auth:sanctum'],   // <-- your normal login guard
],
'except' => ['api/login', 'api/register', 'secure-bridge/handshake'],
```

Protect your real API routes as usual:

```php
Route::middleware('secure-bridge')->group(function () {
    Route::get('/api/profile', ...);
    // ...
});
```

### Step 2 — install the browser client

```bash
npm install secure-bridge-client
```

### Step 3 — call the handshake right after login

This is the only new code you write. After your normal login returns a token:

```js
import SecureBridge from 'secure-bridge-client';

async function afterLogin(authToken) {
  // ask the server for this session's signing key (kept in memory only)
  await SecureBridge.handshake('/secure-bridge/handshake', {
    headers: { Authorization: 'Bearer ' + authToken },
  });

  // from now on, every request you send is signed automatically
  SecureBridge.installFetch();        // for fetch()
  // or: SecureBridge.installAxios(axios);  // if you use axios
}
```

That's it — your normal `fetch`/`axios` calls now work exactly as before, but signed. For the Angular interceptor and full per-framework snippets, see [EXAMPLES.md](EXAMPLES.md) and [INTEGRATION.md](INTEGRATION.md).

> If a request ever comes back with status **412 `handshake_required`** (the key expired), just call `SecureBridge.handshake(...)` again and retry. That's normal.

---

## Setup C — quick and simple (internal tools)

**Only if** it's an internal/dev tool and you just want to deter casual tampering and bots. The key lives in your JavaScript, so a determined person *can* read it — that's the trade-off for simplicity.

`.env`:
```env
SECURE_BRIDGE_KEY_SOURCE=static
```

Browser:
```js
import SecureBridge from 'secure-bridge-client';
SecureBridge.configure({
  key: 'PASTE_THE_BASE64_PART_OF_SECURE_BRIDGE_KEY_HERE',
  sign: true,
});
SecureBridge.installFetch();
```

If this app is public-facing or handles anything sensitive, use **Setup B** instead — it's only a little more work and much safer.

---

## 4. How do I know it's working?

Run this on the server:

```bash
php artisan secure-bridge:doctor
```

It checks your configuration and prints a sample signature so you can confirm the browser and server agree. If something's misconfigured, it tells you in plain English.

While developing locally, you can also add `SECURE_BRIDGE_DEBUG=true` to your `.env` — then if a request is rejected, the log explains *exactly* why.

---

## 5. Common messages and what they mean

| You see… | It means… | Fix |
|---|---|---|
| `412 handshake_required` | Token mode, but the browser hasn't fetched its key yet (or it expired) | Call `SecureBridge.handshake(...)` after login, then retry |
| `400 missing_signature` | The route is protected but the request wasn't signed | Make sure you called `installFetch()`/`installAxios()`, or that the route should really be protected |
| `400 invalid_signature` | The signature didn't match | Usually the request body or URL changed after signing — for axios/jQuery GETs, put query params **in the URL string** (see [INTEGRATION.md](INTEGRATION.md)) |
| `400 stale_timestamp` | The device clock is off by more than 5 minutes | Sync the clock, or raise `SECURE_BRIDGE_WINDOW` |
| `409 replay` | The same request was sent twice | Don't re-send the identical signed request; each one is single-use |

---

## 6. Want more?

- **Pick features per route** (sign only, encrypt only, etc.) → [EXAMPLES.md](EXAMPLES.md#per-route-server-options-pick-features-per-route)
- **Per-framework code** (React, Vue, Angular versions, jQuery, Svelte, Node) → [INTEGRATION.md](INTEGRATION.md)
- **Keeping the key safe / XSS / the strongest setups** → [SECURING-THE-KEY.md](SECURING-THE-KEY.md)
- **Every config option** → the [README configuration table](../README.md#configuration)

You don't need any of these to get started — the steps above are enough.
