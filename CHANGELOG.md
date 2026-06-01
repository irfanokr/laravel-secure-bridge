# Changelog

All notable changes to `irfanokr/laravel-secure-bridge` are documented here.
This project adheres to [Semantic Versioning](https://semver.org).

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
