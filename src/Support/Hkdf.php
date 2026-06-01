<?php

namespace Irfanokr\SecureBridge\Support;

/**
 * HKDF-SHA256 (RFC 5869).
 *
 * Uses PHP's native hash_hkdf() when available and falls back to a pure-PHP
 * implementation otherwise, so the package runs on any PHP 7.1+ build.
 */
class Hkdf
{
    /**
     * Derive $length bytes of keying material from the input keying material.
     *
     * @param  string $ikm     input keying material (raw bytes)
     * @param  int    $length  number of output bytes
     * @param  string $info    context/application-specific info (domain separation)
     * @param  string $salt    optional salt (raw bytes)
     * @return string raw bytes, exactly $length long
     */
    public static function derive($ikm, $length, $info = '', $salt = '')
    {
        if (function_exists('hash_hkdf')) {
            return hash_hkdf('sha256', $ikm, $length, $info, $salt);
        }

        $hashLen = 32; // SHA-256 output

        if ($salt === '') {
            $salt = str_repeat("\x00", $hashLen);
        }

        // Extract
        $prk = hash_hmac('sha256', $ikm, $salt, true);

        // Expand
        $okm = '';
        $t = '';
        $blockIndex = 1;
        while (strlen($okm) < $length) {
            $t = hash_hmac('sha256', $t . $info . chr($blockIndex), $prk, true);
            $okm .= $t;
            $blockIndex++;
        }

        return substr($okm, 0, $length);
    }
}
