# secure-bridge-client

Framework-agnostic browser client for [`irfanokr/laravel-secure-bridge`](https://github.com/irfanokr/laravel-secure-bridge).

It implements the **v1 wire format** — HMAC-SHA256 request signing (timestamp + nonce) and AES-256-GCM payload encryption — using the **Web Crypto API**. No dependencies. Works with `fetch`, `axios`, `jQuery`, and any SPA framework (Angular / React / Vue).

> ⚠️ **Read the threat model** in the [main README](https://github.com/irfanokr/laravel-secure-bridge#threat-model-read-this-first) before relying on this. A key shipped in a public SPA bundle is **not secret** — this layer is defense-in-depth on top of HTTPS, not a replacement for it.

## Install

```bash
npm install secure-bridge-client
```

Or, for a same-origin Laravel Blade app, publish the prebuilt UMD and use the `@secureBridge` Blade directive (no build step) — see the main README.

## Quick start (fetch)

```js
import SecureBridge from 'secure-bridge-client';

SecureBridge.configure({
  key: 'BASE64_MASTER_KEY',   // the base64 part of SECURE_BRIDGE_KEY
  sign: true,
  encryptRequest: false,
  encryptResponse: false,
});

// Transparently sign every same-origin request and decrypt responses:
SecureBridge.installFetch();

const res = await fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ username: 'demo' }),
});
```

## Manual signing (any HTTP client)

```js
const { url, method, headers, body } = await SecureBridge.prepare('POST', '/api/login', { username: 'demo' });
// -> send `body` with `headers` to `url` using whatever client you like
```

See the [main README](https://github.com/irfanokr/laravel-secure-bridge) for axios, jQuery, Angular, React and Vue adapters, the full API, and the wire-format spec.

## License

MIT
