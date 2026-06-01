<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Master key
    |--------------------------------------------------------------------------
    |
    | A single high-entropy master secret. Sign and encryption sub-keys are
    | derived from it with HKDF-SHA256 (domain separated), so you only manage
    | one value. Generate it with:
    |
    |     php artisan secure-bridge:keygen
    |
    | Store it in your .env as SECURE_BRIDGE_KEY=base64:....  A value prefixed
    | with "base64:" is base64-decoded; anything else is used as raw bytes.
    |
    | NOTE: in a public SPA this key ships inside the JavaScript bundle and is
    | therefore NOT secret. Read the "Threat model" section of the README
    | before relying on it. For a meaningful secret use Blade per-session keys
    | (see "session_key" below) or an asymmetric signature driver.
    |
    */
    'key' => env('SECURE_BRIDGE_KEY'),

    /*
    | Previously-valid master keys, accepted for verification/decryption only
    | (never used to sign/encrypt new traffic). Lets you rotate keys without
    | downtime. Comma-separated list in the env, e.g.
    | SECURE_BRIDGE_PREVIOUS_KEYS="base64:aaa,base64:bbb"
    */
    'previous_keys' => array_values(array_filter(array_map('trim', explode(
        ',',
        (string) env('SECURE_BRIDGE_PREVIOUS_KEYS', '')
    )))),

    /*
    |--------------------------------------------------------------------------
    | Feature toggles  (each layer is independent)
    |--------------------------------------------------------------------------
    |
    |   sign_requests    Verify the HMAC signature + timestamp + nonce.
    |   encrypt_request  Expect the request body to be an encrypted envelope
    |                    and decrypt it before it reaches your controller.
    |   encrypt_response Encrypt the JSON response before it leaves the app.
    |
    */
    'sign_requests'    => (bool) env('SECURE_BRIDGE_SIGN', true),
    'encrypt_request'  => (bool) env('SECURE_BRIDGE_ENCRYPT_REQUEST', false),
    'encrypt_response' => (bool) env('SECURE_BRIDGE_ENCRYPT_RESPONSE', false),

    /*
    | Reject any non-HTTPS request (localhost is always allowed for dev). This
    | matters because the whole model is defense-in-depth ON TOP OF TLS — the
    | handshake key and payloads must never travel in clear text.
    */
    'require_https' => (bool) env('SECURE_BRIDGE_REQUIRE_HTTPS', false),

    /*
    |--------------------------------------------------------------------------
    | Drivers (swappable)
    |--------------------------------------------------------------------------
    |
    | Bind your own implementation in a service provider as
    | "secure-bridge.signature.{name}" / "secure-bridge.encryption.{name}" to
    | add a custom driver.
    |
    | signature_driver:
    |   'hmac'  — HMAC-SHA256 with a shared key (default). Simple; pairs with
    |             any key_source.
    |   'ecdsa' — Asymmetric ECDSA P-256. The browser generates a
    |             NON-EXTRACTABLE key pair and registers only its public key at
    |             handshake (requires key_source = 'token'). Injected XSS cannot
    |             exfiltrate the signing key. Strongest option for SPAs.
    |
    */
    'signature_driver'  => env('SECURE_BRIDGE_SIGNATURE_DRIVER', 'hmac'),
    'encryption_driver' => env('SECURE_BRIDGE_ENCRYPTION_DRIVER', 'aes-gcm'),

    /*
    |--------------------------------------------------------------------------
    | Recency window & replay protection
    |--------------------------------------------------------------------------
    |
    | A request is rejected if its timestamp is more than "timestamp_window"
    | seconds away from the server clock. Stripe's documented default is 300s.
    | Never set this to 0 — that disables the recency check entirely.
    |
    | When "replay_protection" is on, each (subject, nonce) pair is remembered
    | in the cache for the length of the window and may be used only once.
    |
    */
    'timestamp_window'  => (int) env('SECURE_BRIDGE_WINDOW', 300),
    'replay_protection' => (bool) env('SECURE_BRIDGE_REPLAY', true),
    'nonce_store'       => env('SECURE_BRIDGE_NONCE_STORE', null), // cache store name; null = default

    /*
    |--------------------------------------------------------------------------
    | Response encoding
    |--------------------------------------------------------------------------
    |
    |   mode = 'field'  Encrypt only the value of "key" in the JSON response
    |                   (the common Laravel { "data": ... } convention).
    |   mode = 'full'   Encrypt the entire JSON body.
    |
    */
    'response_mode' => env('SECURE_BRIDGE_RESPONSE_MODE', 'field'),
    'response_key'  => env('SECURE_BRIDGE_RESPONSE_KEY', 'data'),

    /*
    |--------------------------------------------------------------------------
    | Excluding URLs  (the standard, idiomatic way)
    |--------------------------------------------------------------------------
    |
    | There are two ways to leave a route unprotected, both standard Laravel:
    |
    |   1. Simply DON'T apply the 'secure-bridge' middleware to it. This is the
    |      cleanest approach when you assign the middleware per route/group.
    |
    |   2. When the middleware runs globally (e.g. on the whole 'api' group),
    |      list URI patterns in "except" to skip them — mirroring how Laravel's
    |      own VerifyCsrfToken middleware uses its $except list. If "only" is
    |      non-empty, ONLY matching paths are protected. Patterns use the
    |      Request::is() wildcard syntax (e.g. 'api/webhooks/*').
    |
    | There is intentionally NO client-type / header-based bypass — that would
    | let anyone skip the layer by setting a header. URL patterns are the only
    | bypass.
    |
    */
    'only'   => [],
    'except' => [
        'api/health',
        'telescope*',
        'horizon*',
    ],

    /*
    | Multipart/form-data uploads can't be JSON-enveloped by the browser, so
    | their body is never encrypted. But they ARE still signed (over the
    | method + path + query + timestamp + nonce, with an empty body digest) so
    | a request cannot skip the layer merely by claiming a multipart
    | Content-Type. Set to false to skip multipart entirely (old behaviour) —
    | only do this if those routes are otherwise protected.
    */
    'sign_multipart' => (bool) env('SECURE_BRIDGE_SIGN_MULTIPART', true),

    /*
    |--------------------------------------------------------------------------
    | Where the key comes from  (READ docs/SECURING-THE-KEY.md)
    |--------------------------------------------------------------------------
    |
    | A public SPA cannot hide a secret, so HOW the client gets its key is the
    | whole security story. Pick a source:
    |
    |   'static'   The configured master key. Simplest, but in a decoupled SPA
    |              it ships in the JS bundle and is therefore NOT secret. Fine
    |              for local dev, internal tools, or anti-tampering only.
    |
    |   'session'  Per-session key from the Laravel session (same-origin Blade
    |              apps via @secureBridge). The key never sits in a static
    |              bundle. See "session_key" below.
    |
    |   'token'    Per-session key issued AFTER login to authenticated SPAs via
    |              the handshake endpoint, bound to the bearer token, held only
    |              in browser memory. This is the recommended source for
    |              decoupled React/Angular/Vue apps — no key in the bundle, a
    |              different key per session, useless to anyone reading your JS.
    |              See "handshake" below.
    |
    */
    'key_source' => env('SECURE_BRIDGE_KEY_SOURCE', 'static'),

    /*
    |--------------------------------------------------------------------------
    | Token handshake  (per-session keys for decoupled SPAs)
    |--------------------------------------------------------------------------
    |
    | When enabled, the package registers POST {route} BEHIND your own auth
    | middleware. After a user logs in, the SPA calls it once; the server mints
    | a random key, stores it keyed to the bearer token (in the cache, with a
    | TTL), and returns it. The SPA keeps it in memory and signs with it.
    |
    | Set key_source = 'token' to make the middleware verify against these
    | per-token keys. Remember to exclude your LOGIN route (and this handshake
    | route — done automatically) from signing via "except", since the client
    | has no key until after it authenticates + handshakes.
    |
    */
    'handshake' => [
        'enabled'    => (bool) env('SECURE_BRIDGE_HANDSHAKE', false),
        'route'      => env('SECURE_BRIDGE_HANDSHAKE_ROUTE', 'secure-bridge/handshake'),
        // Your auth middleware — change to 'auth:sanctum', 'auth:api', etc.
        'middleware' => array('auth'),
        'ttl'        => (int) env('SECURE_BRIDGE_HANDSHAKE_TTL', 3600),
        'store'      => env('SECURE_BRIDGE_HANDSHAKE_STORE', null), // cache store; null = default
    ],

    /*
    |--------------------------------------------------------------------------
    | Blade per-session key  (the strong story for server-rendered apps)
    |--------------------------------------------------------------------------
    |
    | Used when key_source = 'session'. The signing/encryption key is a random
    | per-session secret minted server-side and injected into the page by the
    | @secureBridge Blade directive — exactly like the CSRF token. The key
    | never lives in a static JS bundle. (For backward compatibility, setting
    | enabled = true also implies key_source = 'session'.)
    |
    */
    'session_key' => [
        'enabled'   => (bool) env('SECURE_BRIDGE_SESSION_KEY', false),
        'ttl'       => (int) env('SECURE_BRIDGE_SESSION_KEY_TTL', 7200),
        'session_id' => 'secure_bridge_key', // session key name holding the secret
    ],

    /*
    |--------------------------------------------------------------------------
    | Content-Security-Policy + Trusted Types  (XSS *prevention*, opt-in)
    |--------------------------------------------------------------------------
    |
    | Signing/encryption can't protect a page that is already running attacker
    | code — preventing XSS does. Enable this and apply the 'secure-bridge.csp'
    | middleware to your web routes to emit a strict, nonce-based CSP (plus
    | Trusted Types). Put @cspNonce on every <script> tag:
    |
    |     <script nonce="@cspNonce"> ... </script>
    |
    | The literal "{nonce}" in the policy below is replaced per request. Start
    | in report_only mode to find violations before enforcing.
    |
    */
    'csp' => [
        'enabled'       => (bool) env('SECURE_BRIDGE_CSP', false),
        'report_only'   => (bool) env('SECURE_BRIDGE_CSP_REPORT_ONLY', false),
        'trusted_types' => (bool) env('SECURE_BRIDGE_CSP_TRUSTED_TYPES', false),
        'policy'        => "default-src 'self'; "
                         . "script-src 'self' 'nonce-{nonce}' 'strict-dynamic'; "
                         . "object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
        'report_uri'    => env('SECURE_BRIDGE_CSP_REPORT_URI', null),
    ],

    /*
    |--------------------------------------------------------------------------
    | Diagnostics
    |--------------------------------------------------------------------------
    |
    | When true, the middleware logs WHY a signature failed (the canonical
    | string it built vs. what it received). Invaluable while integrating a new
    | client. NEVER enable in production — it can leak request internals.
    |
    */
    'debug' => (bool) env('SECURE_BRIDGE_DEBUG', false),

    /*
    | Dispatch an Irfanokr\SecureBridge\Events\RequestBlocked event whenever a
    | request is rejected, so you can log/alert (the event carries metadata
    | only, never the payload). Set false to disable.
    */
    'events' => (bool) env('SECURE_BRIDGE_EVENTS', true),

    /*
    |--------------------------------------------------------------------------
    | Wire format — header & query parameter names (v1)
    |--------------------------------------------------------------------------
    |
    | Change these only if they collide with something in your stack; the JS
    | client must be configured with the same names.
    |
    */
    'headers' => [
        'signature' => 'X-Sig',
        'timestamp' => 'X-Timestamp',
        'nonce'     => 'X-Nonce',
    ],
    'query' => [
        'signature' => '__sb_sig',
        'timestamp' => '__sb_ts',
        'nonce'     => '__sb_nonce',
    ],
];
