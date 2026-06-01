# secure-bridge-client

Framework-agnostic browser client for [`irfanokr/laravel-secure-bridge`](https://github.com/irfanokr/laravel-secure-bridge) — request signing (HMAC-SHA256 / ECDSA, timestamp + nonce) and optional AES-256-GCM encryption, over the **Web Crypto API**. No dependencies. Works with `fetch`, `XMLHttpRequest`, `axios`, `jQuery`, and Angular / React / Vue / Svelte.

> ⚠️ A key shipped in public JavaScript is **not secret**. This is defense-in-depth on top of HTTPS and your login — not a replacement. See the [security guide](https://github.com/irfanokr/laravel-secure-bridge/blob/main/docs/SECURING-THE-KEY.md).

## Install

```bash
npm install secure-bridge-client
```

## The one call

Once your app has the signing key, **`SecureBridge.install()` signs every request your app makes** — `fetch`, `XMLHttpRequest`, axios, jQuery, Angular `HttpClient` — because it hooks `fetch` and `XMLHttpRequest`, which they all use underneath. You never change individual call sites.

**Separate app with a login (recommended):** fetch a per-session key after login (the *handshake*), then `install()`:

```js
import SecureBridge from 'secure-bridge-client';

await SecureBridge.handshake('/secure-bridge/handshake', {
  headers: { Authorization: 'Bearer ' + token },   // your app's login token
});
SecureBridge.install();
```

Call this **at login and on every page load** — the key lives in memory, so a reload re-fetches it. If a request returns `412 handshake_required`, re-handshake and retry.

**Same-origin Laravel Blade app:** you don't use this package directly — the `@secureBridge` Blade directive wires it for you.

## Full guides

- **Server + setup for your case** → [main README](https://github.com/irfanokr/laravel-secure-bridge#readme)
- **Per-framework client code** (React / Angular / Vue / Svelte / Node / jQuery, with reload + 412 handling) → [docs/INTEGRATION.md](https://github.com/irfanokr/laravel-secure-bridge/blob/main/docs/INTEGRATION.md)
- **Key safety & threat model** → [docs/SECURING-THE-KEY.md](https://github.com/irfanokr/laravel-secure-bridge/blob/main/docs/SECURING-THE-KEY.md)

## License

MIT
