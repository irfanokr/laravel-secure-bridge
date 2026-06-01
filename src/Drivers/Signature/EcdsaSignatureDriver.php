<?php

namespace Irfanokr\SecureBridge\Drivers\Signature;

use Irfanokr\SecureBridge\Contracts\SignatureDriver;
use Irfanokr\SecureBridge\Exceptions\SecureBridgeException;

/**
 * Asymmetric request signing with ECDSA P-256 (NIST P-256 / prime256v1).
 *
 * The browser generates a NON-EXTRACTABLE key pair via the Web Crypto API,
 * registers only the public key with the server (at handshake), and signs each
 * request with the private key — which never leaves the browser and cannot be
 * exfiltrated, even by injected XSS (the script can use it while the page is
 * open, but cannot steal it for offline/replayed reuse).
 *
 * The server only ever VERIFIES, using the registered public key:
 *   - $key       is the client's public key as base64(SPKI DER).
 *   - $signature is base64 of the raw IEEE-P1363 (r||s) signature Web Crypto
 *                produces; we convert it to the ASN.1/DER form OpenSSL expects.
 */
class EcdsaSignatureDriver implements SignatureDriver
{
    public function sign($message, $key)
    {
        throw new SecureBridgeException(
            'EcdsaSignatureDriver: signing happens in the browser with a non-extractable '
            . 'private key; the server only verifies.'
        );
    }

    public function verify($message, $signature, $key)
    {
        $raw = base64_decode((string) $signature, true);
        if ($raw === false || $raw === '') {
            return false;
        }

        $der = self::p1363ToDer($raw);
        if ($der === false) {
            return false;
        }

        $spki = base64_decode((string) $key, true);
        if ($spki === false || $spki === '') {
            return false;
        }

        $publicKey = openssl_pkey_get_public(self::spkiToPem($spki));
        if ($publicKey === false) {
            return false;
        }

        $result = openssl_verify($message, $der, $publicKey, OPENSSL_ALGO_SHA256);

        // openssl_free_key is deprecated/removed on PHP 8+ (GC handles it).
        if (PHP_VERSION_ID < 80000 && is_resource($publicKey)) {
            openssl_free_key($publicKey);
        }

        return $result === 1;
    }

    /**
     * Convert a raw IEEE-P1363 ECDSA signature (r||s, fixed-width) to ASN.1 DER.
     */
    private static function p1363ToDer($sig)
    {
        $len = strlen($sig);
        if ($len === 0 || $len % 2 !== 0) {
            return false;
        }

        $half = (int) ($len / 2);
        $r = self::trimAndPad(substr($sig, 0, $half));
        $s = self::trimAndPad(substr($sig, $half));

        $rEnc = "\x02" . self::derLength(strlen($r)) . $r;
        $sEnc = "\x02" . self::derLength(strlen($s)) . $s;
        $seq = $rEnc . $sEnc;

        return "\x30" . self::derLength(strlen($seq)) . $seq;
    }

    /**
     * Strip leading zero bytes, then prepend one 0x00 if the high bit is set
     * (so the DER INTEGER is interpreted as positive).
     */
    private static function trimAndPad($bytes)
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if (ord($bytes[0]) & 0x80) {
            $bytes = "\x00" . $bytes;
        }

        return $bytes;
    }

    private static function derLength($n)
    {
        if ($n < 0x80) {
            return chr($n);
        }

        $bytes = '';
        while ($n > 0) {
            $bytes = chr($n & 0xff) . $bytes;
            $n >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function spkiToPem($der)
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }
}
