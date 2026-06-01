<?php

namespace Irfanokr\SecureBridge\Support;

use RuntimeException;

/**
 * Turns one or more master secrets into HKDF-derived sign + encryption
 * sub-keys, with domain separation between the two purposes.
 *
 * The first master is the "current" key (used to sign/encrypt new traffic);
 * any extras are accepted for verification/decryption only, which is what
 * makes zero-downtime key rotation possible.
 */
class KeyChain
{
    const SIGN_INFO = 'secure-bridge:sign:v1';
    const ENC_INFO  = 'secure-bridge:enc:v1';

    /** @var string[] raw 32-byte signing keys, current first */
    private $signKeys = array();

    /** @var string[] raw 32-byte encryption keys, current first */
    private $encKeys = array();

    /**
     * @param string[] $masters list of master secrets (already raw bytes)
     */
    public function __construct(array $masters)
    {
        foreach ($masters as $raw) {
            if ($raw === null || $raw === '') {
                continue;
            }
            $this->signKeys[] = Hkdf::derive($raw, 32, self::SIGN_INFO);
            $this->encKeys[]  = Hkdf::derive($raw, 32, self::ENC_INFO);
        }
    }

    /**
     * Build a KeyChain from configured "key" + "previous_keys" values,
     * decoding any "base64:" prefixes.
     */
    public static function fromConfig($current, array $previous = array())
    {
        $masters = array();

        $currentRaw = self::decode($current);
        if ($currentRaw !== null) {
            $masters[] = $currentRaw;
        }

        foreach ($previous as $p) {
            $raw = self::decode($p);
            if ($raw !== null) {
                $masters[] = $raw;
            }
        }

        return new self($masters);
    }

    /**
     * Decode a configured key string into raw bytes. A "base64:" prefix is
     * base64-decoded; anything else is treated as raw bytes.
     *
     * @return string|null
     */
    public static function decode($value)
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (strpos($value, 'base64:') === 0) {
            $decoded = base64_decode(substr($value, 7), true);
            return $decoded === false ? null : $decoded;
        }

        return $value;
    }

    public function isEmpty()
    {
        return count($this->signKeys) === 0;
    }

    public function assertConfigured()
    {
        if ($this->isEmpty()) {
            throw new RuntimeException(
                'SecureBridge: no key configured. Run "php artisan secure-bridge:keygen" '
                . 'and set SECURE_BRIDGE_KEY in your .env.'
            );
        }
    }

    /** @return string current signing key (raw bytes) */
    public function currentSignKey()
    {
        $this->assertConfigured();
        return $this->signKeys[0];
    }

    /** @return string current encryption key (raw bytes) */
    public function currentEncKey()
    {
        $this->assertConfigured();
        return $this->encKeys[0];
    }

    /** @return string[] every accepted signing key (current + previous) */
    public function signKeys()
    {
        return $this->signKeys;
    }

    /** @return string[] every accepted encryption key (current + previous) */
    public function encKeys()
    {
        return $this->encKeys;
    }
}
