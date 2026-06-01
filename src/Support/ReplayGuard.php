<?php

namespace Irfanokr\SecureBridge\Support;

use Illuminate\Contracts\Cache\Repository as CacheRepository;

/**
 * Single-use nonce tracking, backed by any Laravel cache store (use Redis or
 * Memcached for multi-server deployments so the window is shared).
 *
 * A nonce is remembered for the length of the recency window; presenting it a
 * second time within that window is a replay.
 */
class ReplayGuard
{
    /** @var CacheRepository */
    private $cache;

    public function __construct(CacheRepository $cache)
    {
        $this->cache = $cache;
    }

    /**
     * @return bool true if this (subject, nonce) was already seen — a replay.
     */
    public function isReplay($subject, $nonce, $ttlSeconds)
    {
        $cacheKey = 'secure_bridge:nonce:' . hash('sha256', $subject . '|' . $nonce);

        // Cache::add() stores only if the key is absent and returns whether it
        // did so. A DateTime expiry is used because the int-TTL unit (seconds
        // vs minutes) changed across Laravel versions; DateTime is unambiguous
        // on every version.
        $stored = $this->cache->add($cacheKey, 1, $this->expiry($ttlSeconds));

        return $stored === false;
    }

    private function expiry($ttlSeconds)
    {
        $ttl = (int) $ttlSeconds;
        if ($ttl < 1) {
            $ttl = 1;
        }

        if (function_exists('now')) {
            return now()->addSeconds($ttl);
        }

        return (new \DateTime())->setTimestamp(time() + $ttl);
    }
}
