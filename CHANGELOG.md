# Changelog

All notable changes to `irfanokr/laravel-secure-bridge` are documented here.
This project adheres to [Semantic Versioning](https://semver.org).

## [1.6.0] - 2026-06-02

### Added — one call sets up a separate front-end (`SecureBridge.start()`)
- **`SecureBridge.start({ handshake, token, onError, handshakeInit, refreshMargin })`.**
  A single call placed once at app startup wires signing for a decoupled front-end
  (React / Angular / Vue / Svelte / plain JS), the same way an HTTP interceptor or
  `ajaxSetup` does. There is **nothing to wire into the login flow, nothing to re-run
  after a page reload, and no `412` to handle**:
  - The per-session key is fetched **lazily on the first request that carries a token**,
    reused until it nears expiry, and re-fetched automatically.
  - **No token → the request is sent unsigned**, so public and pre-login routes keep
    working and no handshake is attempted before login.
  - Concurrent first requests share **one** in-flight handshake.
  - The key is renewed **proactively** before the server TTL (from the handshake
    `expiresIn`) and whenever the **login token changes**, so a `412` is avoided in
    normal flows for both `fetch` and `XMLHttpRequest`. As a safety net, a `fetch` that
    still receives a `412` transparently re-handshakes and retries once.
  - A failed handshake calls `onError` (if given) and the request proceeds unsigned — it
    never throws into the app's request.

### Compatibility
- `install()`, `installFetch()`, `installXHR()`, `handshake()` and the `@secureBridge`
  Blade directive are **unchanged**. Existing setups (manual `handshake()` + `install()`,
  and Blade session/static mode) keep working exactly as before.
- **No server-side change** — the handshake endpoint already returns the full client
  config including `expiresIn`. `expiresIn` is now carried on the client config.

### Documentation
- README rewritten around the **two center points**: **A — server-rendered Laravel
  (Blade):** one line, `@secureBridge`; **B — separate front-end + Laravel API:** one
  call, `SecureBridge.start({ handshake, token })`. Each path is self-contained, ends
  with a "You're done" and a plain "How to check it worked", with everything else moved
  into a single Advanced pointer.
- `docs/INTEGRATION.md` now leads with `start()` and the per-framework placement of that
  one call; the manual two-call pattern, the `412` wrapper and the reload reasoning are
  kept as a clearly-labelled advanced section; the full config table, refusal codes,
  wire format and glossary live here.
- `docs/SECURING-THE-KEY.md` and `client/README.md` updated to the `start()` form.

## [1.5.2] - 2026-06-02

### Documentation
- **Documented how it works with existing auth (JWT / Sanctum / Passport / sessions).**
  The signing key binds to the bearer token, and `handshake.middleware` takes *your*
  guard (`auth:api`, `jwt.auth`, etc.), so each request carries both your
  `Authorization` (checked by your auth) and the signature (checked by this package)
  as two independent layers. Noted that token refresh/rotation yields a one-off
  `412` → re-handshake with the new token.
- **Documented signing pre-login Blade AJAX** (login / forgot-password / register).
  In session mode the key lives in the (guest) session, so those forms are signed as
  long as the page renders `@secureBridge`; the key carries over the post-login
  session-id regeneration. Clarified: apply to web routes (which have a session), and
  it's in addition to CSRF, not a replacement.

## [1.5.1] - 2026-06-02

### Documentation (a full, coherent rewrite)
- The docs were fragmented across six files that repeated and sometimes
  contradicted each other, with no single "zero-to-working" path. Reworked into
  **one coherent set**:
  - **README** now carries a *complete, self-contained* path for each user type:
    Setup A (Blade) gains a full copy-paste page, a "what to protect / unprotected
    routes still work" example, and a **"Did it work?"** check (look for `X-Sig`
    in DevTools); Setup B gets the server config consolidated into one block.
    Added a plain-English **Glossary**, a **"log when blocked"** recipe, and an
    expanded refusal-codes table. Fixed the `installFetch()` vs `install()` and
    HTTPS-wording inconsistencies.
  - **docs/INTEGRATION.md** rewritten around the **token handshake + `install()`**
    (the recommended path) instead of a static key: the handshake/reload/`412`
    pattern is explained **once**, then each framework (React, Vue, Angular,
    Svelte, plain JS, Node, jQuery) shows only *where* the two calls go. The
    Angular interceptor is now clearly the *response-decryption* option, not a
    requirement. `static` mode is a clearly-labelled "anti-tampering only" section.
  - **docs/SECURING-THE-KEY.md** gains a 30-second "protects / does not" summary
    and a key-source **decision tree** at the top; jargon (Trusted Types, DPoP)
    explained in plain words.
  - **docs/EXAMPLES.md removed** — its content folded into the README and
    INTEGRATION.md so there is one place per topic (no more drift).
  - **client/README.md** trimmed to a short pointer (no duplicated setup).
- No code or behaviour change.

## [1.5.0] - 2026-06-01

### Added — one call signs everything, no code changes
- **`SecureBridge.install()`** patches both `window.fetch` **and** `XMLHttpRequest`.
  Because axios, jQuery, and **Angular's `HttpClient`** all run on `XMLHttpRequest`
  under the hood, this single call signs *every* request an app makes — regardless
  of how it makes them — with **zero call-site changes**. This removes the need to
  rewrite (or wrap) thousands of existing requests.
- **`SecureBridge.installXHR()`** — the `XMLHttpRequest` patch on its own (covers
  raw XHR, axios, jQuery, Angular HttpClient). Idempotent; signs the body as-is and
  preserves the caller's own headers; signs body-less for `FormData` uploads;
  passes through synchronous and cross-origin requests untouched.
- The `@secureBridge` Blade directive now calls `install()`, so a Blade app's
  `fetch`, jQuery, axios and XHR are all wired up by the one directive.

### Changed
- `installAxios()` / `installJQuery()` are now usually unnecessary (kept for the
  rare case of patching one library but not `XMLHttpRequest`); they no-op when the
  XHR patch is already active, so there is no risk of double-signing.

### Robustness (from an adversarial review of the XHR patch)
- **Binary bodies are no longer corrupted.** `Blob` / `ArrayBuffer` / typed-array
  request bodies are now sent as-is and signed body-less (previously a stray
  `JSON.stringify` could turn them into `{}`). Applies to both `fetch` and XHR.
- **`abort()` during the async-signing gap is honoured** — the deferred `send()`
  checks the XHR is still `OPENED` and won't fire on an aborted request.
- **No double-signing with a fetch polyfill.** `install()` skips patching a
  non-native `fetch` (a polyfill built on `XMLHttpRequest`) when XHR is present,
  since the XHR patch already covers it.

### Notes / limitations
- Response *decryption* (only relevant if `encrypt_response` is on) is applied
  automatically for `fetch`; for `XMLHttpRequest`-based requests (axios / jQuery /
  Angular) call `SecureBridge.processResponse(reply)` in your handler, or use the
  Angular interceptor (which decrypts for you). Plain signing needs nothing extra.
- `JSONP` (`<script>`-tag requests, e.g. Angular `HttpClient.jsonp`) is not a normal
  request and is not signed.

## [1.4.4] - 2026-06-01

### Fixed
- **Per-session keys (Blade `@secureBridge`) now actually verify.** When
  `session_key.enabled=true` but `key_source` was left at its default (`static`),
  the `@secureBridge` directive handed the page a per-session key while the
  middleware verified against the *static* key — so every signed request failed.
  `keySource()` now treats the `session_key.enabled` flag as the `session` source
  even when `key_source` is unset or `static` (it still never overrides an explicit
  `token` setup). This is the exact "Setup A" path in the README.

### Tests
- Added `SessionKeyTest` covering the Blade per-session round-trip (the key the
  server hands the page is the same one the middleware verifies, it differs from
  the static key, and it is stable per session / unique across sessions). Both
  scenarios are now explicitly tested — Blade (`SessionKey`) and separate-app
  (`Handshake` / `EcdsaHandshake`). 32 tests pass on PHP 8.3.

### Documentation
- Rewrote Setup B (separate front-end) with a plain-language explanation of the
  handshake and a complete, copy-paste, "where the code goes" example for each
  front-end (plain JavaScript/HTML, React, Angular, Vue) in collapsible boxes —
  no need to leave the README.

## [1.4.3] - 2026-06-01

### Documentation
- **README rewritten in plain, everyday language.** Added a "How it works (in plain
  words)" explanation, a single **minimal setup** that does everything (install →
  one `.env` line → one Blade line → wrap routes), and moved every optional feature
  into a collapsible **Advanced** section (separate front-end apps, encryption,
  per-route features, stronger security, key rotation, full config table, error
  codes, technical/wire-format details). The honest "Is this actually secure?"
  threat model is now in plain language at the bottom. No code or behaviour change.

## [1.4.2] - 2026-06-01

### Changed (integration is now zero-touch)
- **jQuery: `installJQuery($)` transparently wraps `$.ajax`.** Calling it once signs
  every existing `$.ajax` / `$.get` / `$.post` / `$.getJSON` / `$().load()` call with
  **no code changes** (those all call `$.ajax` internally). The old `$.secureAjax`
  helper — which forced you to rewrite each call — is gone as the recommended path
  (kept only as a backward-compatible alias). This matches how `installFetch` and
  `installAxios` already worked, so **no framework requires rewriting your requests**.
- **README rewritten around a single dead-simple quick start.** Install + protect
  routes + one client line (pick Blade or SPA). The standalone beginner guide was
  folded back into the README so there is one place to look.
- **Removed the package-comparison table.** It didn't help anyone implement the
  package and risked mischaracterising other authors' work.
- **Docs reframed around the one central hook per framework** (fetch / axios /
  Angular `HttpInterceptor` / jQuery `$.ajax` / Blade `@secureBridge`), making clear
  you never touch individual call sites.

## [1.4.1] - 2026-06-01

### Documentation
- **Threat-model table now reflects the mitigations.** The README "what it does NOT
  protect against" section previously read as flat limitations; it now shows, per row,
  how the package shrinks each gap (token/session key sources and non-extractable
  ECDSA keys for the bundle-key problem; the bundled CSP + Trusted Types helper and
  non-extractable keys for XSS). No security claim changed — the docs just stopped
  understating what already ships.

## [1.4.0] - 2026-06-01

### Added
- **Per-route feature selection via middleware parameters.** Apply only the
  features a route needs — `secure-bridge:sign`, `secure-bridge:sign,encrypt-response`,
  `secure-bridge:encrypt,https`, `secure-bridge:all`, etc. Anything not named is
  off; no parameters falls back to the config toggles.
- **Observability event** `Irfanokr\SecureBridge\Events\RequestBlocked`,
  dispatched on every rejection (metadata only, never the payload) — listen to
  log/alert. Toggle with the `events` config.
- **docs/EXAMPLES.md** — copy-paste working code for plain AJAX (fetch + jQuery),
  file uploads, the token handshake, and Angular (class + functional interceptor
  + handshake-after-login service).

## [1.3.0] - 2026-06-01

### Changed / Fixed (hardening)
- **Multipart no longer bypasses the layer.** `multipart/form-data` requests are
  now still signed (body-less — the browser owns the boundary) instead of being
  skipped, so a request can't slip past by claiming a multipart Content-Type.
  Body encryption is still skipped for multipart. New `sign_multipart` config
  (replaces `skip_multipart`); the JS client signs `FormData` and `URLSearchParams`
  correctly.
- **HTTPS enforcement.** New `require_https` config rejects non-TLS requests
  (localhost exempt) with `insecure_transport`.
- **Diagnostics.** `secure-bridge:doctor` now warns when the nonce store is not
  persistent/shared (`array`/`file`), which would weaken replay protection.

### Documented
- Honest "Notes & limitations": response-encryption scope, raw-body-after-decrypt
  behaviour, and that the signature covers method/path/query/ts/nonce/body — not
  arbitrary headers.

## [1.2.0] - 2026-06-01

### Added
- **Asymmetric signing — `signature_driver=ecdsa` (ECDSA P-256).** The browser
  generates a NON-EXTRACTABLE keypair, registers only the public key at
  handshake, and signs with a private key it can never export — so injected XSS
  cannot exfiltrate the signing key for offline reuse. Verified end-to-end
  (Web Crypto sign -> PHP openssl_verify, with P1363->DER + SPKI->PEM).
- **CSP + Trusted Types helper** — `csp` config + `secure-bridge.csp` middleware
  emit a strict, nonce-based Content-Security-Policy (optionally Trusted Types),
  with an `@cspNonce` Blade directive. XSS *prevention*, opt-in.
- `docs/SECURING-THE-KEY.md` expanded with an XSS-handling section (own-console
  vs injected XSS; prevent vs limit) and concrete enablement.
- Client `handshake()` now transparently generates the non-extractable keypair
  in ECDSA mode; `signatureDriver` added to the client config/types.

### Removed
- The `request-type` / header-based bypass (it let any caller skip the layer by
  setting a header). Exclude URLs with the `except`/`only` patterns (mirroring
  Laravel's `VerifyCsrfToken`) or per-route `withoutMiddleware('secure-bridge')`.

## [1.1.0] - 2026-06-01

### Added
- **Token handshake / per-session keys for decoupled SPAs** (`key_source=token`).
  After login the SPA calls a server handshake endpoint that mints a random key
  bound to the bearer token (cached, TTL'd) and returns it; the client holds it
  in memory only. No key ever ships in the JS bundle, and every session gets a
  different key. New `handshake` config block, `HandshakeController`,
  `TokenKeyStore`, and a `412 handshake_required` response when a token-mode
  client has not yet fetched a key.
- `SecureBridge.handshake(url, init)` in the JS client.
- `key_source` config (`static` | `session` | `token`) unifying the key sources;
  `session_key.enabled` still implies `session` for backward compatibility.
- New guide `docs/SECURING-THE-KEY.md` explaining how to use the package safely
  in a decoupled JS framework, with the honest XSS/BFF limits.

## [1.0.0] - 2026-06-01

### Added
- Initial release.
- `SecureBridgeMiddleware`: HMAC-SHA256 request signing, timestamp window,
  single-use nonce replay protection, optional AES-256-GCM request decryption
  and response encryption — each independently toggleable.
- HKDF-SHA256 key derivation from a single master key, with multi/rotating-key
  support (`previous_keys`).
- Swappable signature (`hmac`) and encryption (`aes-gcm`) drivers.
- Per-session keys for same-origin Blade apps via the `@secureBridge` directive.
- `secure-bridge:keygen` and `secure-bridge:doctor` (with a deterministic
  client conformance test vector) artisan commands.
- Framework-agnostic `secure-bridge-client` (fetch / axios / jQuery / SPA),
  verified interoperable with the PHP side.
- Support for Laravel 5.5 – 12 and PHP 7.1+.
