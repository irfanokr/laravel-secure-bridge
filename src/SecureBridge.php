<?php

namespace Irfanokr\SecureBridge;

use Illuminate\Contracts\Container\Container;
use Illuminate\Support\Arr;
use Irfanokr\SecureBridge\Contracts\EncryptionDriver;
use Irfanokr\SecureBridge\Contracts\SignatureDriver;
use Irfanokr\SecureBridge\Drivers\Encryption\AesGcmEncryptionDriver;
use Irfanokr\SecureBridge\Drivers\Signature\EcdsaSignatureDriver;
use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Exceptions\DecryptionException;
use Irfanokr\SecureBridge\Exceptions\SecureBridgeException;
use Irfanokr\SecureBridge\Support\KeyChain;
use Irfanokr\SecureBridge\Support\TokenKeyStore;

/**
 * Central service: owns the config, resolves the signature/encryption drivers,
 * builds the per-request key chain (static or per-session) and exposes the
 * high-level sign / verify / encrypt / decrypt operations the middleware and
 * Blade directive use.
 *
 * Resolve it from the container as the "secure-bridge" binding, the
 * SecureBridge::class type-hint, or the SecureBridge facade.
 */
class SecureBridge
{
    const WIRE_VERSION = 'v1';

    /** @var Container */
    private $app;

    /** @var array */
    private $config;

    /** @var SignatureDriver|null */
    private $signatureDriver;

    /** @var EncryptionDriver|null */
    private $encryptionDriver;

    /** @var KeyChain|null */
    private $staticKeyChain;

    /** @var TokenKeyStore|null */
    private $tokenKeyStore;

    public function __construct(Container $app, array $config)
    {
        $this->app = $app;
        $this->config = $config;
    }

    // -- Config ------------------------------------------------------------

    /**
     * @param  string|null $key dot-notation key, or null for the whole array
     */
    public function config($key = null, $default = null)
    {
        if ($key === null) {
            return $this->config;
        }

        return Arr::get($this->config, $key, $default);
    }

    // -- Drivers -----------------------------------------------------------

    public function signatureDriver()
    {
        if ($this->signatureDriver !== null) {
            return $this->signatureDriver;
        }

        $name = $this->signatureDriverName();
        $binding = 'secure-bridge.signature.' . $name;

        if ($this->app->bound($binding)) {
            $this->signatureDriver = $this->app->make($binding);
        } elseif ($name === 'hmac') {
            $this->signatureDriver = new HmacSignatureDriver();
        } elseif ($name === 'ecdsa') {
            $this->signatureDriver = new EcdsaSignatureDriver();
        } else {
            throw new SecureBridgeException(
                'SecureBridge: unknown signature driver [' . $name . ']. '
                . 'Bind it as "' . $binding . '".'
            );
        }

        return $this->signatureDriver;
    }

    public function signatureDriverName()
    {
        return $this->config('signature_driver', 'hmac');
    }

    public function encryptionDriver()
    {
        if ($this->encryptionDriver !== null) {
            return $this->encryptionDriver;
        }

        $name = $this->config('encryption_driver', 'aes-gcm');
        $binding = 'secure-bridge.encryption.' . $name;

        if ($this->app->bound($binding)) {
            $this->encryptionDriver = $this->app->make($binding);
        } elseif ($name === 'aes-gcm') {
            $this->encryptionDriver = new AesGcmEncryptionDriver();
        } else {
            throw new SecureBridgeException(
                'SecureBridge: unknown encryption driver [' . $name . ']. '
                . 'Bind it as "' . $binding . '".'
            );
        }

        return $this->encryptionDriver;
    }

    // -- Keys --------------------------------------------------------------

    /**
     * Resolve the key chain for the current request. When per-session keys are
     * enabled and the request has a session, that short-lived secret is used;
     * otherwise the static configured master key chain is used.
     *
     * @param  \Illuminate\Http\Request|null $request
     */
    public function keyChainForRequest($request = null)
    {
        $source = $this->keySource();

        if ($source === 'token') {
            if ($request !== null) {
                $subject = $this->tokenSubject($request);
                if ($subject !== null) {
                    $master = $this->tokenKeyStore()->lookup($subject);
                    if ($master) {
                        return KeyChain::fromConfig($master);
                    }
                }
            }

            // No issued key yet: return an empty chain. The middleware turns
            // this into a "handshake_required" response so the client knows to
            // call the handshake endpoint.
            return new KeyChain(array());
        }

        if ($source === 'session' && $request !== null && $this->requestHasSession($request)) {
            return KeyChain::fromConfig($this->sessionMaster($request));
        }

        return $this->staticKeyChain();
    }

    /**
     * Effective key source: explicit 'key_source', or 'session' when the
     * legacy session_key.enabled flag is set, otherwise 'static'.
     */
    public function keySource()
    {
        $source = $this->config('key_source');
        if ($source) {
            return $source;
        }

        return $this->config('session_key.enabled', false) ? 'session' : 'static';
    }

    public function staticKeyChain()
    {
        if ($this->staticKeyChain === null) {
            $this->staticKeyChain = KeyChain::fromConfig(
                $this->config('key'),
                (array) $this->config('previous_keys', array())
            );
        }

        return $this->staticKeyChain;
    }

    public function sessionKeyEnabled()
    {
        return (bool) $this->config('session_key.enabled', false);
    }

    private function requestHasSession($request)
    {
        try {
            return method_exists($request, 'hasSession') && $request->hasSession();
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get-or-create the per-session master secret (a "base64:"-prefixed value).
     */
    private function sessionMaster($request)
    {
        $session = $request->session();
        $name = $this->config('session_key.session_id', 'secure_bridge_key');

        $value = $session->get($name);
        if (! $value) {
            $value = 'base64:' . base64_encode(random_bytes(32));
            $session->put($name, $value);
        }

        return $value;
    }

    // -- Token handshake (decoupled SPA per-session keys) ------------------

    /**
     * The cache-store-backed key store for the 'token' source.
     */
    public function tokenKeyStore()
    {
        if ($this->tokenKeyStore === null) {
            $cache = $this->app->make('cache');
            $store = $this->config('handshake.store');
            $repo = $store ? $cache->store($store) : $cache->store();
            $this->tokenKeyStore = new TokenKeyStore($repo, $this->config('handshake.ttl', 3600));
        }

        return $this->tokenKeyStore;
    }

    /**
     * Identify the caller for per-token key binding. Prefers the bearer token
     * (stateless SPA auth); falls back to the authenticated user id.
     *
     * @return string|null
     */
    public function tokenSubject($request)
    {
        $token = $request->bearerToken();
        if ($token) {
            return 'tok:' . hash('sha256', $token);
        }

        try {
            $user = $request->user();
            if ($user !== null) {
                return 'usr:' . $user->getAuthIdentifier();
            }
        } catch (\Exception $e) {
            // no auth resolved
        }

        return null;
    }

    public function issueTokenKey($subject)
    {
        return $this->tokenKeyStore()->issue($subject);
    }

    /**
     * Build the handshake response: a freshly-issued per-session key plus the
     * wire settings the client needs. Returns null if the caller is not
     * authenticated (no resolvable subject).
     *
     * @return array|null
     */
    public function handshakePayload($request)
    {
        $subject = $this->tokenSubject($request);
        if ($subject === null) {
            return null;
        }

        $ecdsa = $this->signatureDriverName() === 'ecdsa';
        $encrypting = (bool) $this->config('encrypt_request', false) || (bool) $this->config('encrypt_response', false);

        $payload = array(
            'signatureDriver' => $this->signatureDriverName(),
            'key'             => null,
            'expiresIn'       => (int) $this->config('handshake.ttl', 3600),
            'sign'            => (bool) $this->config('sign_requests', true),
            'encryptRequest'  => (bool) $this->config('encrypt_request', false),
            'encryptResponse' => (bool) $this->config('encrypt_response', false),
            'responseMode'    => $this->config('response_mode', 'field'),
            'responseKey'     => $this->config('response_key', 'data'),
            'window'          => (int) $this->config('timestamp_window', 300),
            'headers'         => $this->config('headers'),
            'query'           => $this->config('query'),
        );

        if ($ecdsa) {
            // The browser registers its non-extractable public key; it signs
            // with the private key, so no signing key is returned.
            $publicKey = $request->input('publicKey');
            if (! is_string($publicKey) || $publicKey === '') {
                return array('error' => 'missing_public_key');
            }
            $this->tokenKeyStore()->putPublicKey($subject, $publicKey);

            // A symmetric key is only needed if payload encryption is on.
            if ($encrypting) {
                $raw = KeyChain::decode($this->issueTokenKey($subject));
                $payload['key'] = $raw === null ? null : base64_encode($raw);
            }
        } else {
            $raw = KeyChain::decode($this->issueTokenKey($subject));
            $payload['key'] = $raw === null ? null : base64_encode($raw);
        }

        return $payload;
    }

    // -- High level operations --------------------------------------------

    /**
     * Verify a "v1=<sig>" signature value against every accepted key.
     */
    public function verifyCanonical($canonical, $signatureValue, KeyChain $keyChain)
    {
        $signature = $this->stripVersionTag($signatureValue);
        if ($signature === null) {
            return false; // missing or non-v1 scheme (downgrade protection)
        }

        $driver = $this->signatureDriver();
        foreach ($keyChain->signKeys() as $key) {
            if ($driver->verify($canonical, $signature, $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verify a request signature, choosing the right key material for the
     * driver: the per-subject public key for ECDSA, or the symmetric key chain
     * for HMAC.
     */
    public function verifyRequest($canonical, $signatureValue, $request, KeyChain $keyChain)
    {
        $signature = $this->stripVersionTag($signatureValue);
        if ($signature === null) {
            return false;
        }

        if ($this->signatureDriverName() === 'ecdsa') {
            $subject = $request !== null ? $this->tokenSubject($request) : null;
            if ($subject === null) {
                return false;
            }
            $spki = $this->tokenKeyStore()->getPublicKey($subject);
            if (! $spki) {
                return false;
            }

            return $this->signatureDriver()->verify($canonical, $signature, $spki);
        }

        $driver = $this->signatureDriver();
        foreach ($keyChain->signKeys() as $key) {
            if ($driver->verify($canonical, $signature, $key)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the request has the key material it needs. Returns null when
     * ready, or array(status, message, code) describing what is missing.
     */
    public function readinessError($request, KeyChain $keyChain, $signing = null, $encrypting = null)
    {
        $source = $this->keySource();
        if ($signing === null) {
            $signing = (bool) $this->config('sign_requests', true);
        }
        if ($encrypting === null) {
            $encrypting = (bool) $this->config('encrypt_request', false) || (bool) $this->config('encrypt_response', false);
        }
        $ecdsa = $this->signatureDriverName() === 'ecdsa';

        if ($signing && $ecdsa) {
            $subject = $request !== null ? $this->tokenSubject($request) : null;
            if ($subject === null || ! $this->tokenKeyStore()->getPublicKey($subject)) {
                return array(412, 'Secure handshake required before signed requests.', 'handshake_required');
            }
        }

        $needsSymmetric = $encrypting || ($signing && ! $ecdsa);
        if ($needsSymmetric && $keyChain->isEmpty()) {
            if ($source === 'token') {
                return array(412, 'Secure handshake required.', 'handshake_required');
            }

            return array(500, 'SecureBridge key is not configured on the server.', 'no_key');
        }

        return null;
    }

    /**
     * Produce a "v1=<sig>" signature value with the current key.
     */
    public function signCanonical($canonical, KeyChain $keyChain)
    {
        return self::WIRE_VERSION . '=' . $this->signatureDriver()->sign($canonical, $keyChain->currentSignKey());
    }

    public function encryptString($plaintext, KeyChain $keyChain)
    {
        return $this->encryptionDriver()->encrypt($plaintext, $keyChain->currentEncKey());
    }

    /**
     * Decrypt an envelope, trying each accepted key (supports rotation).
     *
     * @throws DecryptionException
     */
    public function decryptString($envelope, KeyChain $keyChain)
    {
        $driver = $this->encryptionDriver();
        $last = null;

        foreach ($keyChain->encKeys() as $key) {
            try {
                return $driver->decrypt($envelope, $key);
            } catch (\Exception $e) {
                $last = $e;
            }
        }

        if ($last !== null) {
            throw $last;
        }

        throw new DecryptionException('SecureBridge: no encryption key configured.');
    }

    private function stripVersionTag($value)
    {
        $value = (string) $value;
        $eq = strpos($value, '=');
        if ($eq === false) {
            return null; // require an explicit version tag
        }

        $scheme = substr($value, 0, $eq);
        if ($scheme !== self::WIRE_VERSION) {
            return null; // only v1 accepted — ignore unknown/older schemes
        }

        return substr($value, $eq + 1);
    }

    // -- Client bootstrap (for the @secureBridge Blade directive) ----------

    /**
     * The configuration object handed to the JavaScript client. In per-session
     * mode this carries the short-lived session key; otherwise the static key.
     *
     * @param  \Illuminate\Http\Request|null $request
     * @return array
     */
    public function clientConfig($request = null)
    {
        if ($request === null && function_exists('request')) {
            $request = request();
        }

        if ($this->sessionKeyEnabled() && $request !== null && $this->requestHasSession($request)) {
            $master = $this->sessionMaster($request);
        } else {
            $master = $this->config('key');
        }

        $raw = KeyChain::decode($master);

        return array(
            'key'             => $raw === null ? null : base64_encode($raw),
            'sign'            => (bool) $this->config('sign_requests', true),
            'encryptRequest'  => (bool) $this->config('encrypt_request', false),
            'encryptResponse' => (bool) $this->config('encrypt_response', false),
            'responseMode'    => $this->config('response_mode', 'field'),
            'responseKey'     => $this->config('response_key', 'data'),
            'window'          => (int) $this->config('timestamp_window', 300),
            'headers'         => $this->config('headers'),
            'query'           => $this->config('query'),
        );
    }

    /**
     * The per-request CSP nonce set by CspMiddleware, or '' if not active.
     */
    public function cspNonce()
    {
        $binding = \Irfanokr\SecureBridge\Http\Middleware\CspMiddleware::NONCE_BINDING;

        return $this->app->bound($binding) ? (string) $this->app->make($binding) : '';
    }
}
