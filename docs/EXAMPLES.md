# Working examples (copy-paste)

Full, runnable JavaScript for the two cases asked about most — **plain AJAX** and **Angular** — plus the per-route server options. For React/Vue/Svelte see [INTEGRATION.md](INTEGRATION.md).

Every example assumes the server has a key:

```bash
php artisan secure-bridge:keygen
php artisan vendor:publish --tag=secure-bridge-config
```

---

## 1. Plain JavaScript / AJAX

### 1a. Same-origin Blade page (zero JS to write)

Server (`.env`):
```env
SECURE_BRIDGE_KEY_SOURCE=session
SECURE_BRIDGE_SESSION_KEY=true
```

Publish the client asset once: `php artisan vendor:publish --tag=secure-bridge-assets`.

Blade layout `<head>` (after jQuery if you use it):
```blade
@secureBridge
```

That injects the client + a per-session key and auto-wires `window.fetch` and `jQuery`. Your existing AJAX is now signed — nothing else to change:
```html
<script>
  // Plain fetch — already signed by @secureBridge:
  fetch('/api/profile', {
    method: 'POST',
    body: JSON.stringify({ name: 'Ali' }),
  })
  .then(r => r.json())
  .then(data => console.log(data));   // already decrypted if encrypt_response is on
</script>
```

### 1b. Decoupled SPA / static page — token handshake (recommended)

Server (`.env`):
```env
SECURE_BRIDGE_KEY_SOURCE=token
SECURE_BRIDGE_HANDSHAKE=true
SECURE_BRIDGE_SIGNATURE_DRIVER=ecdsa     # non-extractable key — best for XSS
```
`config/secure-bridge.php`:
```php
'handshake' => ['enabled' => true, 'route' => 'secure-bridge/handshake', 'middleware' => ['auth:sanctum']],
'except'    => ['api/login', 'secure-bridge/handshake'],   // login has no key yet
```

Browser:
```html
<script src="/vendor/secure-bridge/secure-bridge.umd.js"></script>
<script>
  async function boot() {
    // 1. Your normal login → get the auth token.
    const login = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'me@example.com', password: 'secret' }),
    }).then(r => r.json());
    const token = login.token;

    // 2. Handshake: server issues a per-session key (or, in ecdsa mode, the
    //    browser generated a non-extractable keypair and registered its public
    //    key). The key lives only in memory.
    await SecureBridge.handshake('/secure-bridge/handshake', {
      headers: { Authorization: 'Bearer ' + token },
    });

    // 3. From now on every same-origin request is signed automatically.
    SecureBridge.installFetch();

    // 4. Use fetch normally.
    const profile = await fetch('/api/profile', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token },
      body: JSON.stringify({ name: 'Ali' }),
    }).then(r => r.json());
    console.log(profile);
  }
  boot();
</script>
```

If a later request returns `412 handshake_required` (key expired), just call `SecureBridge.handshake(...)` again and retry.

### 1c. Without monkey-patching fetch (full manual control)

```js
SecureBridge.configure({ key: 'BASE64_KEY', sign: true });

const p = await SecureBridge.prepare('POST', '/api/orders?lang=en', { item: 42 });
const res = await fetch(p.url, { method: p.method, headers: p.headers, body: p.body });
let data = await res.json();
data = await SecureBridge.processResponse(data);  // decrypts if encrypt_response is on
```

### 1d. jQuery `$.ajax`

`$.ajax` can't sign synchronously, so use the helper (already installed by `@secureBridge`, or call `SecureBridge.installJQuery(window.jQuery)`):

```js
$.secureAjax({
  url: '/api/orders',
  type: 'POST',
  data: { item: 42 },
}).then(function (data) {
  // resolved with the (decrypted) response payload
  console.log(data);
});
```

### 1e. File upload (multipart) — just pass FormData

```js
const fd = new FormData();
fd.append('avatar', fileInput.files[0]);
fd.append('caption', 'hello');

// installFetch handles it: the upload is SIGNED (body-less) but not encrypted.
await fetch('/api/avatar', { method: 'POST', body: fd });
```

---

## 2. Angular

Works in Angular 4.3+ (class interceptor) and 15+ (functional). Full class version:

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
        const cloned = p.body !== undefined
          ? req.clone({ setHeaders: p.headers, body: p.body })  // send the exact signed string
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

A small service that performs the handshake right after login:

```ts
// secure-bridge.service.ts
import { Injectable } from '@angular/core';
import SecureBridge from 'secure-bridge-client';
import { environment } from '../environments/environment';

@Injectable({ providedIn: 'root' })
export class SecureBridgeService {
  /** Call once, immediately after your login returns a token. */
  async handshake(token: string): Promise<void> {
    await SecureBridge.handshake(`${environment.apiBase}/secure-bridge/handshake`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  }
}
```

```ts
// in your auth/login flow
await this.http.post('/api/login', creds).toPromise().then(async (res: any) => {
  this.store.token = res.token;
  await this.secureBridge.handshake(res.token);   // now the interceptor can sign
});
```

Register the interceptor.

**NgModule (Angular ≤ 17):**
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

**Standalone (Angular 15+) — functional interceptor:**
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
```ts
// main.ts
import { provideHttpClient, withInterceptors } from '@angular/common/http';
bootstrapApplication(AppComponent, {
  providers: [provideHttpClient(withInterceptors([secureBridgeInterceptor]))],
});
```

For `static` key mode (no handshake) configure once at startup instead:
```ts
SecureBridge.configure({ key: environment.sbKey, sign: true });
```

---

## 3. React / Vue / Svelte

`SecureBridge.installFetch()` (or `installAxios(axios)`) once at startup, plus the handshake after login — full snippets in [INTEGRATION.md](INTEGRATION.md).

---

## Per-route server options (pick features per route)

Apply only the features a given route needs — anything not listed is off:

```php
use Illuminate\Support\Facades\Route;

// Sign only (no encryption):
Route::middleware('secure-bridge:sign')->post('/api/login', [AuthController::class, 'login']);

// Sign + encrypt the response only:
Route::middleware('secure-bridge:sign,encrypt-response')->get('/api/profile', ...);

// Encrypt both directions + require HTTPS, but don't sign:
Route::middleware('secure-bridge:encrypt,https')->post('/api/secret', ...);

// Everything:
Route::middleware('secure-bridge:all')->post('/api/transfer', ...);

// No params → use the config defaults:
Route::middleware('secure-bridge')->group(function () { /* ... */ });
```

Tokens: `sign`, `encrypt-request`, `encrypt-response`, `encrypt` (both), `all`, `https`, `no-https`. The client must be configured with the matching features (the handshake response already carries them).

To leave a route unprotected, just don't apply the middleware (or add its URI to the `except` list, or `->withoutMiddleware('secure-bridge')`).

## Observability

Listen for rejections (no payload is exposed):

```php
use Irfanokr\SecureBridge\Events\RequestBlocked;
use Illuminate\Support\Facades\Event;

Event::listen(RequestBlocked::class, function (RequestBlocked $e) {
    logger()->warning('SecureBridge blocked', [
        'code' => $e->code, 'status' => $e->status,
        'ip' => $e->request->ip(), 'path' => $e->request->path(),
    ]);
});
```
