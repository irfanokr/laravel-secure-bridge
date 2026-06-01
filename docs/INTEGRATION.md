# Front-end integration guide

**The whole point: you wire this in ONE place, and your existing requests keep working unchanged.** You do **not** rewrite your `fetch` / `$http` / `$.ajax` / axios calls — there could be hundreds of them. Every framework already has a single central hook, and this package plugs into it:

| Framework | The one hook you use | Your existing calls |
|---|---|---|
| Plain `fetch` (any framework) | `SecureBridge.installFetch()` — patches `window.fetch` | unchanged |
| axios (Vue, React, …) | `SecureBridge.installAxios(axios)` — adds an interceptor | unchanged |
| Angular `HttpClient` | one `HttpInterceptor`, registered once | unchanged |
| jQuery / legacy AJAX | `SecureBridge.installJQuery($)` — wraps `$.ajax` | unchanged |
| Blade app | the `@secureBridge` directive — wires fetch **and** jQuery for you | unchanged |

Add the one-time setup for your framework below and you're done. (`SecureBridge.configure({ key })` runs once at startup; the Blade directive and the `token` handshake do it for you.)

> **The only quirk:** Web Crypto is asynchronous, so signing is async. The central hooks above all handle that internally — you never touch a Promise. You only deal with async if you deliberately choose the manual `SecureBridge.prepare()` path for a one-off request.

---

## Getting the key into the client

| You serve the SPA from… | Recommended delivery |
|---|---|
| A fully **decoupled** build (Netlify/Vercel/S3) with login | **`token` handshake** — `await SecureBridge.handshake('/secure-bridge/handshake', { headers: { Authorization: 'Bearer ' + token } })` after login. No key in the bundle. **Recommended.** |
| The **same** Laravel app (Blade `index`) | `@secureBridge` Blade directive (auto-config, **per-session keys**) — nothing else to do |
| Decoupled, anti-tampering only (no login) | Build-time env var, e.g. `import.meta.env.VITE_SB_KEY` — `static` source; **the key is not secret**, use only for anti-tampering/bot-deterrence |

> ⚠️ A key in a decoupled bundle (`static` source) is **not secret**. For anything beyond anti-tampering, use the **`token` handshake** — full guide: **[docs/SECURING-THE-KEY.md](SECURING-THE-KEY.md)**.

```js
// reading a meta tag, if you injected one
const key = document.querySelector('meta[name="sb-key"]')?.content;
SecureBridge.configure({ key, sign: true });
```

---

## Vanilla JS / `fetch` (any framework, no adapter)

```js
import SecureBridge from 'secure-bridge-client';
SecureBridge.configure({ key: KEY, sign: true, encryptResponse: false });
SecureBridge.installFetch();          // every same-origin fetch() is now signed
```

Manual (no monkey-patching):

```js
const p = await SecureBridge.prepare('POST', '/api/login', { username: 'demo' });
const res = await fetch(p.url, { method: p.method, headers: p.headers, body: p.body });
let json = await res.json();
json = await SecureBridge.processResponse(json);   // no-op unless encryptResponse is on
```

---

## Angular

The client is identical across Angular versions; only **how you register an interceptor** changed. Pick the block for your version.

### Angular 4.3 – 14 (and still valid in 15–18): class `HttpInterceptor`

```ts
// secure-bridge.interceptor.ts
import { Injectable } from '@angular/core';
import {
  HttpInterceptor, HttpRequest, HttpHandler, HttpEvent, HttpResponse,
} from '@angular/common/http';
import { Observable, from, of } from 'rxjs';
import { switchMap, mergeMap, map } from 'rxjs/operators';
import SecureBridge from 'secure-bridge-client';

@Injectable()
export class SecureBridgeInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    return from(SecureBridge.prepare(req.method, req.urlWithParams, req.body)).pipe(
      switchMap((p) => {
        // p.body is the exact signed string; send it verbatim so the digest matches.
        const cloned = p.body !== undefined
          ? req.clone({ setHeaders: p.headers, body: p.body })
          : req.clone({ setHeaders: p.headers });

        return next.handle(cloned).pipe(
          mergeMap((event: HttpEvent<any>) => {
            if (event instanceof HttpResponse && event.body && typeof event.body === 'object') {
              return from(SecureBridge.processResponse(event.body)).pipe(
                map((decoded) => event.clone({ body: decoded }))
              );
            }
            return of(event);
          })
        );
      })
    );
  }
}
```

Register it (NgModule):

```ts
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { SecureBridgeInterceptor } from './secure-bridge.interceptor';

@NgModule({
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: SecureBridgeInterceptor, multi: true },
  ],
})
export class AppModule {}
```

Configure the client once (e.g. in `AppComponent` constructor or an `APP_INITIALIZER`):

```ts
SecureBridge.configure({ key: environment.sbKey, sign: true });
```

### Angular 15+: functional interceptor (`HttpInterceptorFn`)

```ts
// secure-bridge.interceptor.ts
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
```

Register (standalone bootstrap):

```ts
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { secureBridgeInterceptor } from './secure-bridge.interceptor';

bootstrapApplication(AppComponent, {
  providers: [provideHttpClient(withInterceptors([secureBridgeInterceptor]))],
});
```

### AngularJS 1.x (legacy)

```js
app.config(['$httpProvider', function ($httpProvider) {
  $httpProvider.interceptors.push(['$q', function ($q) {
    return {
      request: function (config) {
        var url = config.url; // put query params in the URL string
        return $q.when(SecureBridge.prepare(config.method, url, config.data)).then(function (p) {
          config.headers = angular.extend(config.headers || {}, p.headers);
          if (p.body !== undefined) {
            config.data = p.body;
            config.transformRequest = [function (d) { return d; }];
          }
          return config;
        });
      },
      response: function (response) {
        return $q.when(SecureBridge.processResponse(response.data)).then(function (d) {
          response.data = d;
          return response;
        });
      },
    };
  }]);
}]);
```

---

## React

No adapter needed — install once at startup:

```jsx
// index.jsx
import SecureBridge from 'secure-bridge-client';
SecureBridge.configure({ key: process.env.REACT_APP_SB_KEY, sign: true });
SecureBridge.installFetch();   // covers fetch(), axios-on-fetch, react-query, SWR, etc.
```

Using axios:

```jsx
import axios from 'axios';
SecureBridge.configure({ key: KEY });
SecureBridge.installAxios(axios);   // put query params in the URL, not config.params
```

A reusable hook (manual style):

```jsx
function useSecureFetch() {
  return useCallback(async (method, url, body) => {
    const p = await SecureBridge.prepare(method, url, body);
    const res = await fetch(p.url, { method: p.method, headers: p.headers, body: p.body });
    return SecureBridge.processResponse(await res.json());
  }, []);
}
```

---

## Vue

### Vue 3

```js
// main.js
import { createApp } from 'vue';
import axios from 'axios';
import SecureBridge from 'secure-bridge-client';

SecureBridge.configure({ key: import.meta.env.VITE_SB_KEY, sign: true });
SecureBridge.installAxios(axios);            // or SecureBridge.installFetch();

const app = createApp(App);
app.config.globalProperties.$http = axios;
app.mount('#app');
```

### Vue 2

```js
import Vue from 'vue';
import axios from 'axios';
import SecureBridge from 'secure-bridge-client';

SecureBridge.configure({ key: process.env.VUE_APP_SB_KEY, sign: true });
SecureBridge.installAxios(axios);
Vue.prototype.$http = axios;
```

---

## Svelte / SvelteKit

```js
// +layout.js  (or a client-only module)
import { browser } from '$app/environment';
import SecureBridge from 'secure-bridge-client';

if (browser) {                         // Web Crypto runs in the browser
  SecureBridge.configure({ key: import.meta.env.VITE_SB_KEY, sign: true });
  SecureBridge.installFetch();
}
```

> SSR note: don't sign during server-side rendering — configure inside a `browser`/client guard so the key never touches the SSR output.

---

## jQuery / AJAX

Call `installJQuery` **once**. It transparently wraps `$.ajax` — and since `$.get`, `$.post`, `$.getJSON` and `$().load()` all call `$.ajax` internally, **every existing call is signed with no edits**:

```js
SecureBridge.configure({ key: KEY, sign: true });
SecureBridge.installJQuery(window.jQuery);   // <-- the only line you add

// ...all your EXISTING code keeps working, now signed automatically:
$.ajax({ url: '/api/login', type: 'POST', data: { username: 'demo' } })
  .done(function (data) { /* decrypted if encryptResponse is on */ });

$.post('/api/orders', { item: 42 });
$.getJSON('/api/me');
```

Inside a Blade app, `@secureBridge` calls `installJQuery(window.jQuery)` for you — there is nothing to wire at all.

> Because signing is async, the wrapped `$.ajax` returns a jQuery **promise** (`.done` / `.fail` / `.then` / `.always`, plus a best-effort `.abort()`). That covers virtually all real-world usage. If some code depends on *synchronous* jqXHR object properties, use `SecureBridge.prepare()` manually for just those calls.

---

## Node.js / server-to-server

The same client runs on Node 18+ (it uses the global Web Crypto):

```js
const SecureBridge = require('secure-bridge-client');
SecureBridge.configure({ key: process.env.SB_KEY, sign: true });

const p = await SecureBridge.prepare('POST', 'https://api.example.com/api/sync', { ok: true });
await fetch(p.url, { method: p.method, headers: p.headers, body: p.body });
```

(For routes that should never be signed — webhooks, health checks — add the URI pattern to the `except` list in the config, or simply don't apply the `secure-bridge` middleware to them.)

---

## Cross-cutting notes

- **Query parameters:** the signed path+query must equal what the browser actually sends. With `fetch`/Angular `urlWithParams` this is automatic. With **axios `config.params`** or **jQuery `data` on GET**, the lib serializes params *after* signing — so put query params **in the URL string** for signed GETs, or use `SecureBridge.signUrl(url)` for download links.
- **File uploads:** `multipart/form-data` bodies are **still signed** (body-less — the browser owns the boundary), so they can't bypass the layer; only the *encryption* of the body is skipped. Just pass a `FormData` as the body and the client handles it. For signed *downloads* use `signUrl()`.
- **Verify your wiring:** run `php artisan secure-bridge:doctor` on the server and confirm your client reproduces the printed `X-Sig` for the given inputs. Set `SECURE_BRIDGE_DEBUG=true` locally to log the exact canonical string the server built when a signature fails.
- **Clock skew:** the client uses the browser clock for the timestamp. A device clock off by more than `timestamp_window` (default 300s) will be rejected — widen the window or sync the clock.
