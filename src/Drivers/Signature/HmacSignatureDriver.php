<?php

namespace Irfanokr\SecureBridge\Drivers\Signature;

use Irfanokr\SecureBridge\Contracts\SignatureDriver;

/**
 * HMAC-SHA256 request signing — the standards-blessed symmetric default
 * (registered as hmac-sha256 in RFC 9421 / IANA).
 *
 * Symmetric signing provides integrity + authenticity of the request to a
 * party that already holds the key. It provides NO non-repudiation, and the
 * key cannot be hidden inside a public SPA bundle — see the README threat
 * model. For a client-held secret with no shared-key problem, supply an
 * asymmetric driver (Ed25519/ECDSA) via the "secure-bridge.signature.{name}"
 * container binding.
 */
class HmacSignatureDriver implements SignatureDriver
{
    public function sign($message, $key)
    {
        // Lowercase hex digest.
        return hash_hmac('sha256', $message, $key);
    }

    public function verify($message, $signature, $key)
    {
        $expected = $this->sign($message, $key);

        // Constant-time comparison (RFC/GitHub guidance) — never use ==.
        return hash_equals($expected, strtolower((string) $signature));
    }
}
