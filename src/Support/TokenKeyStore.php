<?php

namespace Irfanokr\SecureBridge\Support;

use Illuminate\Contracts\Cache\Repository as CacheRepository;

/**
 * Issues and looks up per-session master keys for the "token" key source.
 *
 * After a user authenticates, the SPA calls the handshake endpoint; this store
 * mints a random master, remembers it in the cache keyed to the caller's
 * subject (a hash of the bearer token), and hands it back. Subsequent signed
 * requests are verified against that per-session key — so no key ever ships in
 * the JS bundle and every session has a different one.
 */
class TokenKeyStore
{
    /** @var CacheRepository */
    private $cache;

    /** @var int */
    private $ttl;

    public function __construct(CacheRepository $cache, $ttl)
    {
        $this->cache = $cache;
        $this->ttl = (int) $ttl > 0 ? (int) $ttl : 3600;
    }

    /**
     * Mint and store a fresh master for the subject. Returns a "base64:" value.
     */
    public function issue($subject)
    {
        $master = 'base64:' . base64_encode(random_bytes(32));
        $this->cache->put($this->cacheKey($subject), $master, $this->expiry());

        return $master;
    }

    /**
     * @return string|null the stored "base64:" master, or null if none/expired.
     */
    public function lookup($subject)
    {
        return $this->cache->get($this->cacheKey($subject));
    }

    public function revoke($subject)
    {
        $this->cache->forget($this->cacheKey($subject));
    }

    private function cacheKey($subject)
    {
        return 'secure_bridge:token_key:' . hash('sha256', (string) $subject);
    }

    private function expiry()
    {
        if (function_exists('now')) {
            return now()->addSeconds($this->ttl);
        }

        return (new \DateTime())->setTimestamp(time() + $this->ttl);
    }
}
