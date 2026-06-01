<?php

namespace Irfanokr\SecureBridge\Console;

use Illuminate\Console\Command;
use Irfanokr\SecureBridge\SecureBridge;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\KeyChain;

/**
 * Health check + a deterministic conformance test vector. Run it after install
 * and hand the printed vector to whoever writes the front-end client so they
 * can confirm their HKDF + canonicalization + HMAC match the server byte for
 * byte — the single biggest source of "invalid signature" frustration.
 */
class DoctorCommand extends Command
{
    protected $signature = 'secure-bridge:doctor';

    protected $description = 'Diagnose the SecureBridge install and print a client conformance test vector';

    public function handle(SecureBridge $bridge)
    {
        $ok = true;

        $this->line('SecureBridge diagnostics');
        $this->line('========================');

        $ok = $this->check('ext-openssl loaded', extension_loaded('openssl')) && $ok;

        $methods = function_exists('openssl_get_cipher_methods')
            ? array_map('strtolower', openssl_get_cipher_methods())
            : array();
        $ok = $this->check('aes-256-gcm cipher available', in_array('aes-256-gcm', $methods, true)) && $ok;

        $this->check('hash_hkdf() native HKDF (else polyfill)', function_exists('hash_hkdf'), true);

        $kc = $bridge->staticKeyChain();
        $keyOk = ! $kc->isEmpty();
        $ok = $this->check('master key configured (SECURE_BRIDGE_KEY)', $keyOk) && $ok;

        try {
            $store = $bridge->config('nonce_store');
            $cache = $this->laravel->make('cache');
            ($store ? $cache->store($store) : $cache->store())->get('secure_bridge:doctor');
            $this->check('cache store reachable (replay protection)', true);
        } catch (\Exception $e) {
            $this->check('cache store reachable (replay protection)', false, true);
        }

        if ($bridge->config('replay_protection', true)) {
            $storeName = $bridge->config('nonce_store') ?: $this->laravel['config']->get('cache.default');
            $driver = $this->laravel['config']->get('cache.stores.' . $storeName . '.driver');
            // 'array' is per-process (replay protection effectively off); 'file'
            // is persistent but NOT shared across multiple servers.
            $persistentShared = ! in_array($driver, array('array', 'file'), true);
            $this->check(
                'nonce store is persistent & shared [' . $storeName . ':' . $driver . '] (use redis/memcached/database in prod)',
                $persistentShared,
                true
            );
        }

        $this->line('');
        $this->line('Configuration:');
        $keys = array(
            'sign_requests', 'encrypt_request', 'encrypt_response',
            'signature_driver', 'encryption_driver',
            'timestamp_window', 'replay_protection',
            'response_mode', 'response_key',
        );
        foreach ($keys as $k) {
            $this->line(sprintf('  %-20s : %s', $k, $this->stringify($bridge->config($k))));
        }
        $this->line(sprintf('  %-20s : %s', 'session_key.enabled', $this->stringify($bridge->config('session_key.enabled'))));

        if ($keyOk) {
            $this->printVector($bridge, $kc);
        } else {
            $this->line('');
            $this->warn('No key configured — run "php artisan secure-bridge:keygen" to enable the test vector.');
        }

        return $ok ? 0 : 1;
    }

    protected function printVector(SecureBridge $bridge, KeyChain $kc)
    {
        $raw = KeyChain::decode($bridge->config('key'));

        $method = 'POST';
        $path   = '/api/login';
        $query  = 'lang=en';
        $ts     = '1700000000';
        $nonce  = 'testnonce123';
        $body   = '{"username":"demo"}';

        $canonical = Canonicalizer::build($method, $path, $query, $ts, $nonce, hash('sha256', $body));
        $sig = $bridge->signCanonical($canonical, $kc);

        $this->line('');
        $this->line('Conformance test vector (your JS client MUST reproduce X-Sig):');
        $this->line('  master key (base64) : ' . base64_encode($raw));
        $this->line('  method              : ' . $method);
        $this->line('  path                : ' . $path);
        $this->line('  query               : ' . $query);
        $this->line('  request body        : ' . $body);
        $this->line('  X-Timestamp         : ' . $ts);
        $this->line('  X-Nonce             : ' . $nonce);
        $this->line('  canonical (\\n shown) : ' . str_replace("\n", '\\n', $canonical));
        $this->line('  X-Sig               : ' . $sig);
    }

    protected function check($label, $pass, $warnOnly = false)
    {
        if ($pass) {
            $this->line('  [ OK ]   ' . $label);
        } elseif ($warnOnly) {
            $this->line('  [WARN]   ' . $label);
        } else {
            $this->line('  [FAIL]   ' . $label);
        }

        return $pass || $warnOnly;
    }

    protected function stringify($value)
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }

        return (string) $value;
    }
}
