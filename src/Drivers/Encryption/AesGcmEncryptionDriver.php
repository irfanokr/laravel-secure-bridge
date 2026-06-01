<?php

namespace Irfanokr\SecureBridge\Drivers\Encryption;

use Irfanokr\SecureBridge\Contracts\EncryptionDriver;
use Irfanokr\SecureBridge\Exceptions\DecryptionException;
use Irfanokr\SecureBridge\Exceptions\SecureBridgeException;

/**
 * AES-256-GCM authenticated encryption, interoperable with the Web Crypto API
 * (SubtleCrypto) in the browser.
 *
 * Envelope (dot-separated, all base64 standard alphabet):
 *
 *     v1.<base64(iv)>.<base64(ciphertext || tag)>
 *
 *  - 12-byte (96-bit) IV, freshly random per message (NIST SP 800-38D).
 *  - 16-byte (128-bit) authentication tag, appended to the ciphertext exactly
 *    the way SubtleCrypto.encrypt() returns it; PHP's openssl returns the tag
 *    separately, so we concatenate it.
 *  - AAD binds the wire-format version so it can't be stripped/downgraded.
 *
 * GCM is authenticated: a tampered ciphertext fails to decrypt rather than
 * silently producing garbage — the reason to prefer it over hand-rolled
 * XOR/keystream schemes.
 */
class AesGcmEncryptionDriver implements EncryptionDriver
{
    const VERSION = 'v1';
    const CIPHER  = 'aes-256-gcm';
    const IV_LEN  = 12;
    const TAG_LEN = 16;
    const AAD     = 'secure-bridge:v1';

    public function encrypt($plaintext, $key)
    {
        $iv = random_bytes(self::IV_LEN);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::AAD,
            self::TAG_LEN
        );

        if ($ciphertext === false) {
            throw new SecureBridgeException('SecureBridge: AES-256-GCM encryption failed.');
        }

        return self::VERSION
            . '.' . base64_encode($iv)
            . '.' . base64_encode($ciphertext . $tag);
    }

    public function decrypt($envelope, $key)
    {
        $parts = explode('.', (string) $envelope);
        if (count($parts) !== 3 || $parts[0] !== self::VERSION) {
            throw new DecryptionException('SecureBridge: malformed ciphertext envelope.');
        }

        $iv   = base64_decode($parts[1], true);
        $blob = base64_decode($parts[2], true);

        if ($iv === false || $blob === false
            || strlen($iv) !== self::IV_LEN
            || strlen($blob) <= self::TAG_LEN) {
            throw new DecryptionException('SecureBridge: malformed ciphertext envelope.');
        }

        $tag        = substr($blob, -self::TAG_LEN);
        $ciphertext = substr($blob, 0, strlen($blob) - self::TAG_LEN);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::AAD
        );

        if ($plaintext === false) {
            throw new DecryptionException('SecureBridge: decryption or authentication failed.');
        }

        return $plaintext;
    }
}
