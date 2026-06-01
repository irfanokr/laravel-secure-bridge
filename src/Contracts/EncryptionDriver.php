<?php

namespace Irfanokr\SecureBridge\Contracts;

interface EncryptionDriver
{
    /**
     * Encrypt a plaintext string into a self-describing envelope.
     *
     * @param  string $plaintext
     * @param  string $key raw key bytes
     * @return string envelope (e.g. "v1.<b64 iv>.<b64 ciphertext+tag>")
     */
    public function encrypt($plaintext, $key);

    /**
     * Decrypt an envelope produced by encrypt().
     *
     * @param  string $envelope
     * @param  string $key raw key bytes
     * @return string plaintext
     *
     * @throws \Irfanokr\SecureBridge\Exceptions\DecryptionException on any
     *         malformed envelope or authentication failure.
     */
    public function decrypt($envelope, $key);
}
