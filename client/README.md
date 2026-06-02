# secure-bridge-client

Framework-agnostic browser client for [`irfanokr/laravel-secure-bridge`](https://github.com/irfanokr/laravel-secure-bridge) — request signing (HMAC-SHA256 / ECDSA, timestamp + nonce) and optional AES-256-GCM encryption, over the **Web Crypto API**. No dependencies. Works with `fetch`, `XMLHttpRequest`, `axios`, `jQuery`, and Angular / React / Vue / Svelte.

> ⚠️ A key shipped in public JavaScript is **not secret**. This is defense-in-depth on top of HTTPS and your login — not a replacement. See the [security guide](https://github.com/irfanokr/laravel-secure-bridge/blob/main/docs/SECURING-THE-KEY.md).

## Install

```bash
npm install secure-bridge-client
```

## The one call

**Separate app with a login (recommended):** call `SecureBridge.start({...})` **once** at app startup. It fetches a per-session key on the first request (the *handshake*), keeps it in memory, renews it before it expires, and signs **every** request your app makes — `fetch`, `XMLHttpRequest`, axios, jQuery, Angular `HttpClient` — because it hooks `fetch` and `XMLHttpRequest`, which they all use underneath. You never change individual call sites, and there's nothing to wire into login or reloads and no `412` to handle.

```js
import SecureBridge from 'secure-bridge-client';

SecureBridge.start({
  handshake: '/secure-bridge/handshake',
  token: () => localStorage.getItem('auth_token'),   // however your app stores its login token
});
```

A request made before login (no token yet) is sent unsigned, so public/login routes keep working.

**Same-origin Laravel Blade app:** you don't use this package directly — the `@secureBridge` Blade directive wires it for you.

## Full guides

- **Server + setup for your case** → [main README](https://github.com/irfanokr/laravel-secure-bridge#readme)
- **Per-framework client code** (React / Angular / Vue / Svelte / Node / jQuery — where the one call goes) → [docs/INTEGRATION.md](https://github.com/irfanokr/laravel-secure-bridge/blob/main/docs/INTEGRATION.md)
- **Key safety & threat model** → [docs/SECURING-THE-KEY.md](https://github.com/irfanokr/laravel-secure-bridge/blob/main/docs/SECURING-THE-KEY.md)

## License

MIT
