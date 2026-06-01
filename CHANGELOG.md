# Changelog

All notable changes to `irfanokr/laravel-secure-bridge` are documented here.
This project adheres to [Semantic Versioning](https://semver.org).

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
