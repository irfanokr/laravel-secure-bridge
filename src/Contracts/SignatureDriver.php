<?php

namespace Irfanokr\SecureBridge\Contracts;

interface SignatureDriver
{
    /**
     * Produce a signature for the given canonical message.
     *
     * @param  string $message canonical string to sign
     * @param  string $key     raw key bytes
     * @return string signature value (no version tag)
     */
    public function sign($message, $key);

    /**
     * Verify a signature in constant time.
     *
     * @param  string $message   canonical string that was signed
     * @param  string $signature signature value received (no version tag)
     * @param  string $key       raw key bytes
     * @return bool
     */
    public function verify($message, $signature, $key);
}
