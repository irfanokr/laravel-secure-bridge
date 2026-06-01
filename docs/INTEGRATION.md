# Front-end integration guide (separate front-end apps)

This guide is the **client side** for a **separate** front-end — React, Angular, Vue, Svelte, plain JavaScript, or Node — that calls a Laravel API.

> Using Laravel **Blade** pages instead? You don't need this file. The `@secureBridge` directive wires everything for you — see **[README → Setup A](../README.md#setup-a)**.

The matching **server** setup (token handshake) is in **[README → Setup B](../README.md#setup-b)**. Read that first; this guide picks up on the browser side.

---

## One call signs everything

```js
SecureBridge.install();
```

`install()` patches the browser's two request engines — `window.fetch` and `XMLHttpRequest`. Because **axios, jQuery, and Angular's `HttpClient` all use `XMLHttpRequest` underneath**, this one call signs every request your app makes. **You never edit a single `fetch` / `$.ajax` / `$http` / axios call** — no matter how many you have.

> - **Response *decryption*** is automatic only for `fetch`. With `encrypt_response` on, decrypt XHR/axios/jQuery/Angular replies with `SecureBridge.processResponse(reply)`, or use the axios/Angular interceptor shown under [Response decryption](#response-decryption). Plain signing (the default) needs nothing.
> - **JSONP** (`<script>`-tag requests) is not signed — it isn't a normal request.

---

## The one pattern: handshake, then install

The signing key must **not** live in your downloadable code, so your app fetches it from the server **after login** (the *handshake*), keeps it in memory, and turns signing on. This is the **same two lines for every framework** — put them in a small shared function:

```js
// secureBridge.js  (import this everywhere you need it)
import SecureBridge from 'secure-bridge-client';   // npm install secure-bridge-client

export async function startSecureBridge(token) {
  // 1. Get this session's signing key from the server (the handshake):
  await SecureBridge.handshake('/secure-bridge/handshake', {
    headers: { Authorization: 'Bearer ' + token },   // your app's normal login token
  });
  // 2. Turn on signing for EVERY request your app makes:
  SecureBridge.install();
}
```

**Call `startSecureBridge(token)` in TWO places:**

1. Right after a successful **login** (you have a fresh token).
2. At **app startup / page load**, whenever a saved login token already exists.

Why both? The key lives in memory, so a **page reload wipes it** — but your login token survives (in your cookie/storage), so on reload you simply fetch a fresh key. (Full reasoning: [README → page reloads](../README.md#setup-b).)

### Handling an expired key (`412`)

If a request returns **`412 handshake_required`** (the key's lifetime expired), fetch a new key and retry. A tiny `fetch` wrapper does it for you:

```js
async function apiFetch(url, init, token) {
  let res = await fetch(url, init);
  if (res.status === 412) {            // key expired → re-handshake, retry once
    await startSecureBridge(token);
    res = await fetch(url, init);
  }
  return res;
}
```

(With axios, do the same inside a response interceptor that catches a `412`.)

---

## Where the two calls go, per framework

The signing itself is automatic after `install()`. All you wire per framework is **where** `startSecureBridge(token)` runs (login + startup).

### React

```jsx
import { useEffect } from 'react';
import { startSecureBridge } from './secureBridge';

// 1) after a successful login:
async function onLoginSuccess(token) {
  localStorage.setItem('auth_token', token);   // your token, your choice where to keep it
  await startSecureBridge(token);
}

// 2) at startup (in your root component), if already logged in:
useEffect(() => {
  const token = localStorage.getItem('auth_token');
  if (token) startSecureBridge(token);
}, []);
```

Every `fetch`/axios call in the app is now signed — nothing else changes.

### Vue (3 and 2)

```js
// after login:
await startSecureBridge(token);

// at startup (main.js, or App's created/setup), if a token exists:
const token = localStorage.getItem('auth_token');
if (token) startSecureBridge(token);
```

### Angular

`install()` already signs every `HttpClient` request (it uses `XMLHttpRequest`), so you do **not** need an interceptor just to sign. Wire the handshake after login and at startup:

```ts
// after login (e.g. in your AuthService):
await startSecureBridge(token);
```
```ts
// at startup — register an APP_INITIALIZER in your providers:
import { APP_INITIALIZER } from '@angular/core';
import { startSecureBridge } from './secure-bridge';

{ provide: APP_INITIALIZER, multi: true, useFactory: () => () => {
    const token = localStorage.getItem('auth_token');
    return token ? startSecureBridge(token) : Promise.resolve();
}}
```

(Only if you enable `encrypt_response` and want replies decrypted automatically, add the interceptor under [Response decryption](#response-decryption).)

### Svelte / SvelteKit

```js
// a client-only module, or +layout.js guarded by `browser`:
import { browser } from '$app/environment';
if (browser) {
  const token = localStorage.getItem('auth_token');
  if (token) startSecureBridge(token);
}
// and call startSecureBridge(token) in your login action
```

> SSR note: only call it in the browser — never during server-side rendering, so no key touches SSR output.

### Plain JavaScript (no build tools)

```html
<script src="https://unpkg.com/secure-bridge-client"></script>
<script>
  async function startSecureBridge(token) {
    await SecureBridge.handshake('/secure-bridge/handshake', { headers: { Authorization: 'Bearer ' + token } });
    SecureBridge.install();
  }

  // after login: save the token, then startSecureBridge(token)
  // on every page load: re-fetch a key if already logged in
  window.addEventListener('load', function () {
    var token = localStorage.getItem('auth_token');
    if (token) startSecureBridge(token);
  });
</script>
```

### jQuery

`install()` already covers jQuery (it uses `XMLHttpRequest`). After `startSecureBridge()` runs, your existing `$.ajax` / `$.get` / `$.post` / `$.getJSON` calls are signed — **nothing else to wire**. (Because signing is async, the wrapped calls return a jQuery promise: `.done`/`.fail`/`.then`/`.always` plus a best-effort `.abort()`.)

### Node.js / server-to-server

Server-to-server typically uses a **`static` shared key** (both ends are servers, so the key is genuinely secret — no handshake needed):

```js
const SecureBridge = require('secure-bridge-client');   // Node 18+ (global Web Crypto)
SecureBridge.configure({ key: process.env.SB_KEY, sign: true });

const p = await SecureBridge.prepare('POST', 'https://api.example.com/api/sync', { ok: true });
await fetch(p.url, { method: p.method, headers: p.headers, body: p.body });
```

---

<a id="response-decryption"></a>
## Response decryption (only if `encrypt_response` is on)

`install()` signs every request and auto-decrypts responses **for `fetch`**. For XHR-based libraries (axios / jQuery / Angular) you either call `SecureBridge.processResponse(reply)` on the data you receive, or register an interceptor that does it for you.

**axios** — one call adds request signing *and* response decryption:

```js
SecureBridge.installAxios(axios);   // put query params in the URL string, not config.params
```

**Angular** — an interceptor that signs *and* decrypts (use it instead of `install()` if you prefer the Angular-native way). Pick the form for your version:

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

If you use the Angular interceptor, you still call `startSecureBridge(token)` (the handshake) at login and startup — the interceptor needs the key the handshake provides.

---

## Static key mode (no login — anti-tampering only)

If your app has **no login** and you only want anti-tampering / bot-deterrence (**not** real secrecy), skip the handshake and use a build-time key:

```js
SecureBridge.configure({ key: import.meta.env.VITE_SB_KEY, sign: true });
SecureBridge.install();
```

> ⚠️ A key in downloadable JavaScript is **not secret** — anyone can read it. Use this only for low-stakes/internal cases. For anything sensitive, use the handshake above. Full reasoning: **[SECURING-THE-KEY.md](SECURING-THE-KEY.md)**.

---

## Cross-cutting notes

- **Query parameters on signed GETs:** the signed path+query must equal what the browser actually sends. With `fetch` and Angular `urlWithParams` this is automatic. With **axios `config.params`** or **jQuery `data` on a GET**, params are serialized *after* signing — so put them **in the URL string**, or use `SecureBridge.signUrl(url)` for download links.
- **File uploads:** `FormData` bodies are **still signed** (body-less — the browser owns the multipart boundary); only *encryption* of the body is skipped. Just pass the `FormData` as the body.
- **Verify your wiring:** run `php artisan secure-bridge:doctor` on the server; set `SECURE_BRIDGE_DEBUG=true` locally to log exactly why a signature failed.
- **Clock skew:** the client uses the browser clock for the timestamp. A device clock off by more than `timestamp_window` (default 300s) is rejected — sync the clock or widen the window.
