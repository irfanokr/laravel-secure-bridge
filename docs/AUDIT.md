# Security & Usability Audit

Audit of `irfanokr/laravel-secure-bridge` covering the PHP middleware/crypto
layer (`src/`), the configuration surface (`config/secure-bridge.php`), and the
browser client (`client/dist/secure-bridge.umd.js`).

**Overall:** the package is well-engineered and unusually honest about its own
threat model. The cryptographic primitives are used correctly (HKDF domain
separation, AES-256-GCM with a fresh 96-bit IV and verified tag, constant-time
HMAC comparison, version-tagged downgrade protection, non-extractable ECDSA
keys). The findings below are about *gaps around the edges* of an otherwise
sound design, plus integrator-experience papercuts — not a broken core.

Severity scale: **High** (exploitable weakening of a stated guarantee) ·
**Medium** (weakening under realistic conditions) · **Low** (narrow / hard to
hit) · **Info** (defense-in-depth / clarity).

---

## Security findings

### S1 — Replay protection is bypassable by changing source IP / User-Agent · **Medium**

`SecureBridgeMiddleware::subject()` builds the replay-cache partition key from
the **client-controlled** request origin when there is no bearer token:

```php
// src/Http/Middleware/SecureBridgeMiddleware.php
protected function subject($request)
{
    $token = $request->bearerToken();
    if ($token) {
        return 'tok:' . $token;
    }
    list($path) = Canonicalizer::splitTarget($request->getRequestUri());
    return implode('|', array(
        (string) $request->ip(),
        (string) $request->userAgent(),
        $request->getMethod(),
        $path,
    ));
}
```

The nonce is then remembered per-subject (`ReplayGuard::isReplay($subject, $nonce, …)`).
A nonce is a random 128-bit value — it is meant to be **single-use globally**,
but here it is single-use *only within the same IP+UA+method+path bucket*.

**Impact:** in `session` (Blade) and `static` key modes there is no bearer
token, so a captured-but-still-valid signed request (within the 300 s
`timestamp_window`) replayed from a **different IP or with a different
User-Agent** lands in a different bucket, is not recognized as a replay, and is
accepted. TLS protects the request in transit, but the realistic vector is a
signed request that leaks to a log, a browser extension, or a corporate proxy
and is then replayed from elsewhere — exactly the scenario the nonce is
supposed to stop. This silently weakens a guarantee the README states plainly
("A copied request can't be re-sent later").

The `token` mode (decoupled SPAs) is unaffected because the subject is the
bearer token.

**Recommendation:** key the replay namespace on the *signing identity*, not the
network origin. The cleanest cross-mode fix is to derive the subject from a
fingerprint of the key that actually verified the request (e.g.
`'key:' . substr(hash('sha256', $matchedSignKey), 0, 16)`), falling back to a
global namespace. That yields: global single-use in static mode (correct),
per-session in session mode (correct), per-token in token mode (unchanged) —
and removes any dependence on spoofable IP/UA. Have `verifyRequest()` return
*which* key matched so the middleware can use it for the subject.

---

### S2 — Replay nonce TTL can lapse while the timestamp is still valid · **Low**

```php
// SecureBridgeMiddleware::verifyInbound()
$ttl = max(1, $window - abs(time() - (int) $ts));
if ($this->replayGuard()->isReplay($this->subject($request), (string) $nonce, $ttl)) { … }
```

A timestamp is accepted while `abs(time - ts) <= window`, i.e. up to
`ts + window`. The nonce must therefore be remembered until `ts + window`. For a
**future-dated** timestamp (legitimate client clock skew, within the window),
`abs(time - ts)` *shortens* the TTL, so the nonce is forgotten before the
timestamp stops being accepted — a narrow window in which the same request can
be replayed. The boundary case for past timestamps is likewise tight.

**Recommendation:** remember the nonce for the full window (optionally
`window + max_skew`). The simplest correct value is just `$window` seconds — the
extra retention is harmless and closes the gap.

---

### S3 — `require_https` localhost exemption trusts the spoofable `Host` header · **Low/Medium**

```php
// SecureBridgeMiddleware::isSecure()
$host = strtolower((string) $request->getHost());
return $host === 'localhost' || $host === '127.0.0.1' || $host === '::1' || $host === '[::1]';
```

`getHost()` is derived from the `Host` header (or `X-Forwarded-Host` when
trusted proxies are configured). Unless the app sets `TrustHosts`/trusted hosts,
an attacker hitting a plain-HTTP endpoint with `Host: localhost` passes the
HTTPS gate. In a typical deployment the edge proxy overwrites `Host`, but apps
that pass it through (or have misconfigured `TrustProxies`) are exposed, and
`require_https` is precisely the control a security-conscious integrator turns
on expecting it to be airtight.

**Recommendation:** gate the dev exemption on something not client-controlled —
e.g. `$request->isSecure()` OR `app()->environment('local')`, or a dedicated
`allow_insecure_localhost` config flag — rather than on the request host. At
minimum, document the assumption.

---

### S4 — `encrypt_request` does not actually *require* encryption · **Low**

```php
// SecureBridgeMiddleware::decryptInbound()
if (! is_array($json) || count($json) !== 1
    || ! isset($json['__cipher']) || ! is_string($json['__cipher'])) {
    // Not an encrypted envelope — leave the request untouched …
    return null;
}
```

With `encrypt_request = true`, a non-enveloped (plaintext) body is silently
accepted, not rejected. This is a deliberate rollout aid (plain and encrypted
clients coexist), but it means the confidentiality control can be downgraded to
"off" by simply not encrypting — there is no strict mode. (When signing is also
on, the plaintext body is still authenticated, so this is a confidentiality-
enforcement gap, not an integrity one.)

**Recommendation:** add an opt-in `encrypt_request_strict` that rejects
write-method requests carrying a non-`__cipher` body with a clear refusal code.

---

### S5 — AES-GCM AAD is a fixed constant with no direction/context binding · **Info**

`AAD = 'secure-bridge:v1'` is identical for requests and responses, and the same
HKDF-derived `encKey` is used in both directions. A captured response envelope
is, cryptographically, a well-formed request envelope (and vice-versa). There is
no practical exploit without the key, but binding the direction into the AAD
(`…:req` / `…:res`) — or domain-separating request vs. response encryption keys
in HKDF — is a cheap defense-in-depth upgrade. (Note: changing the AAD/info is a
wire-format break; gate it behind the version tag.)

---

### S6 — In `ecdsa` mode the *encryption* key is still exfiltratable · **Info**

`handshakePayload()` returns a normal, extractable symmetric key for AES-GCM
whenever encryption is enabled, even in `ecdsa` signature mode. The docs market
ecdsa as a key that "can't even be copied out" — true for the **signing** key
(non-extractable `CryptoKey`), but the **encryption** key handed back in the
handshake *is* readable by injected script. Worth a one-line clarification in
`docs/SECURING-THE-KEY.md` so the non-extractable guarantee isn't over-read.

---

### Positive security observations

- `hash_equals()` for HMAC verification (no timing oracle).
- HKDF-SHA256 with distinct `info` for sign vs. enc keys (domain separation).
- AES-256-GCM, random 12-byte IV per message, authentication tag verified on
  decrypt; malformed envelopes rejected before `openssl_decrypt`.
- Signature value requires an explicit `v1=` tag; unknown/older schemes are
  refused — real downgrade protection.
- Non-extractable ECDSA P-256 keys via Web Crypto; server only ever verifies.
- Multipart cannot be used to skip the layer (signed body-less by default).
- `OPTIONS` preflight and the handshake route are excluded deliberately and
  correctly; there is no header-based bypass.
- The threat-model documentation is candid and accurate about what signing does
  and does not buy in a public client.

---

## Usability findings

### U1 — Response decryption is inconsistent between `fetch` and XHR/axios/jQuery

`install()` (the headline "one call, no code changes") patches `XMLHttpRequest`,
which is what axios and jQuery ride on. But with `encrypt_response = true`,
`installFetch` auto-decrypts replies while `installXHR` does **not** — the caller
must invoke `processResponse()` by hand. So the "every request just works"
promise is only fully true for `fetch` when response encryption is on. This is
documented in code/INTEGRATION comments, but it is a sharp edge against the
README's framing.

**Recommendation:** either implement response decryption at the XHR layer
(hook `onreadystatechange`/`load` and rewrite `responseText` when the content
type is JSON and `encrypt_response` is set), or surface this caveat prominently
in the README's Section B, not just deep in the integration doc.

### U2 — `secure-bridge:doctor` doesn't flag incoherent configurations

The doctor prints config values but doesn't cross-check the combinations that
cause the exact silent failures integrators hit:

- `signature_driver = ecdsa` requires `key_source = token` (else the server has
  no public key to verify against → perpetual `412`).
- `key_source = token` requires `handshake.enabled = true`.
- `session` mode requires a session-bearing route (web middleware), not `api`.
- `require_https = true` while `$request->isSecure()` is false behind an
  un-trusted TLS terminator → all traffic blocked.

A handful of assertions here would convert "why is everything 412?" debugging
sessions into a single actionable line.

### U3 — No built-in rate limiting on the handshake / failure paths

There is no throttle on the handshake endpoint or on repeated signature
failures. Brute-forcing HMAC/ECDSA is infeasible, so this isn't a crypto risk,
but the handshake mints cache entries per call and is a natural abuse target.
Recommend documenting a `throttle:` middleware on the handshake route (and
optionally on protected groups).

### U4 — Static key is emitted to the page even when it isn't needed

`clientConfig()` always includes `key` in the `@secureBridge` output when one is
configured, even if `sign_requests = false` and no encryption is on. Minor, but
it puts a key in the HTML for no functional reason. Consider omitting `key` when
neither signing nor encryption is active.

### U5 — `require_https` defaults to `false`

Reasonable for zero-config local dev, but a defense-in-depth package whose whole
premise is "on top of TLS" arguably wants to nudge harder toward HTTPS in
production — at least a doctor warning when `require_https=false` and the app is
not in `local`.

### Positive usability observations

- The `secure-bridge:doctor` conformance test vector is an excellent idea — it
  directly attacks the #1 integration pain (client/server canonicalization
  drift).
- `start()` / `install()` genuinely deliver one-call setup for both Blade and
  decoupled-SPA paths, including transparent key refresh and 412 re-handshake.
- Config is thoroughly commented; `README` + `SECURING-THE-KEY` + `INTEGRATION`
  form a coherent, honest guide.
- Client and `package.json` versions are in lockstep (1.6.0).

---

## Suggested remediation order

1. **S1** (replay subject) — highest security value; fixes a stated guarantee.
2. **S2** (nonce TTL) — one-line correctness fix, pairs naturally with S1.
3. **U2** (doctor coherence checks) — largest support-burden reduction.
4. **S3 / S4** — config-flag-gated hardening, low risk to existing users.
5. **U1** (XHR response decryption) — closes the biggest "no code changes" gap.
6. **S5 / S6 / U3–U5** — documentation and defense-in-depth polish.

> None of S1–S4 is a wire-format break; they can ship without bumping the `v1`
> envelope. S5's AAD change *is* a wire break and must be version-gated.
