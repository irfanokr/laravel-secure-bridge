# Changelog

All notable changes to `irfanokr/laravel-secure-bridge` are documented here.
This project adheres to [Semantic Versioning](https://semver.org).

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
