<?php

namespace Irfanokr\SecureBridge\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Irfanokr\SecureBridge\SecureBridge;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\ReplayGuard;

/**
 * The one middleware that does everything, driven by config toggles:
 *
 *   inbound :  verify signature  ->  check timestamp  ->  reject replays
 *              ->  decrypt request body
 *   outbound:  encrypt the JSON response
 *
 * Register it as the "secure-bridge" alias (auto-registered by the service
 * provider) and apply it to a route/group, or push it into a global stack and
 * scope it with the "only"/"except" config patterns.
 */
class SecureBridgeMiddleware
{
    /** @var SecureBridge */
    protected $bridge;

    /** @var Container */
    protected $container;

    /** @var ReplayGuard|null */
    protected $replayGuard;

    public function __construct(SecureBridge $bridge, Container $container)
    {
        $this->bridge = $bridge;
        $this->container = $container;
    }

    public function handle($request, Closure $next)
    {
        if ($this->shouldBypass($request)) {
            return $next($request);
        }

        $keyChain = $this->bridge->keyChainForRequest($request);

        if ($keyChain->isEmpty() && $this->needsKey()) {
            if ($this->bridge->keySource() === 'token') {
                return $this->fail(412, 'Secure handshake required before signed requests.', 'handshake_required');
            }

            return $this->fail(500, 'SecureBridge key is not configured on the server.', 'no_key');
        }

        if ($this->bridge->config('sign_requests', true)) {
            $error = $this->verifyInbound($request, $keyChain);
            if ($error !== null) {
                return $error;
            }
        }

        if ($this->bridge->config('encrypt_request', false)) {
            $error = $this->decryptInbound($request, $keyChain);
            if ($error !== null) {
                return $error;
            }
        }

        $response = $next($request);

        if ($this->bridge->config('encrypt_response', false)) {
            $this->encryptOutbound($response, $keyChain);
        }

        return $response;
    }

    // -- Skip rules --------------------------------------------------------

    protected function shouldBypass($request)
    {
        // CORS preflight never carries a signature.
        if ($request->isMethod('OPTIONS')) {
            return true;
        }

        // The handshake endpoint itself is authenticated by the app, not signed.
        $handshakeRoute = $this->bridge->config('handshake.route');
        if ($handshakeRoute && $request->is(ltrim($handshakeRoute, '/'))) {
            return true;
        }

        // Multipart uploads can't be JSON-enveloped by the client.
        if ($this->bridge->config('skip_multipart', true)) {
            $contentType = (string) $request->header('content-type', '');
            if (stripos($contentType, 'multipart/form-data') === 0) {
                return true;
            }
        }

        // Path scoping.
        $only = (array) $this->bridge->config('only', array());
        if (! empty($only) && ! $this->matchesAny($request, $only)) {
            return true;
        }

        $except = (array) $this->bridge->config('except', array());
        if (! empty($except) && $this->matchesAny($request, $except)) {
            return true;
        }

        return false;
    }

    protected function matchesAny($request, array $patterns)
    {
        foreach ($patterns as $pattern) {
            if ($request->is($pattern)) {
                return true;
            }
        }

        return false;
    }

    protected function needsKey()
    {
        return $this->bridge->config('sign_requests', true)
            || $this->bridge->config('encrypt_request', false)
            || $this->bridge->config('encrypt_response', false);
    }

    // -- Inbound: signature + timestamp + replay ---------------------------

    protected function verifyInbound($request, $keyChain)
    {
        $headerNames = $this->bridge->config('headers');
        $queryNames = $this->bridge->config('query');

        $fromHeader = $request->headers->has($headerNames['signature']);

        if ($fromHeader) {
            $sig = $request->header($headerNames['signature']);
            $ts = $request->header($headerNames['timestamp']);
            $nonce = $request->header($headerNames['nonce']);
            $stripKeys = array();
        } else {
            // Signed download links carry the values in the query string.
            $sig = $request->query($queryNames['signature']);
            $ts = $request->query($queryNames['timestamp']);
            $nonce = $request->query($queryNames['nonce']);
            $stripKeys = array($queryNames['signature'], $queryNames['timestamp'], $queryNames['nonce']);
        }

        if (empty($sig) || empty($ts) || empty($nonce)) {
            return $this->fail(400, 'Missing request signature.', 'missing_signature');
        }

        $window = (int) $this->bridge->config('timestamp_window', 300);
        if (! ctype_digit((string) $ts) || abs(time() - (int) $ts) > $window) {
            return $this->fail(400, 'Request timestamp outside the allowed window.', 'stale_timestamp');
        }

        $canonical = Canonicalizer::fromRequest($request, (string) $ts, (string) $nonce, $stripKeys);

        if (! $this->bridge->verifyCanonical($canonical, $sig, $keyChain)) {
            if ($this->bridge->config('debug', false)) {
                $this->container->make('log')->warning('SecureBridge: signature mismatch', array(
                    'canonical_built' => $canonical,
                    'received_sig'    => $sig,
                    'method'          => $request->getMethod(),
                    'request_uri'     => $request->getRequestUri(),
                ));
            }

            return $this->fail(400, 'Invalid request signature.', 'invalid_signature');
        }

        if ($this->bridge->config('replay_protection', true)) {
            $ttl = max(1, $window - abs(time() - (int) $ts));
            if ($this->replayGuard()->isReplay($this->subject($request), (string) $nonce, $ttl)) {
                return $this->fail(409, 'Replayed request detected.', 'replay');
            }
        }

        return null;
    }

    protected function subject($request)
    {
        $token = $request->bearerToken();
        if ($token) {
            return 'tok:' . $token;
        }

        list($path) = Canonicalizer::splitTarget($request->getRequestUri());

        return implode('|', array(
            (string) $request->ip(),
            (string) $request->userAgent(),
            $request->getMethod(),
            $path,
        ));
    }

    // -- Inbound: decrypt body --------------------------------------------

    protected function decryptInbound($request, $keyChain)
    {
        if (! in_array($request->getMethod(), array('POST', 'PUT', 'PATCH', 'DELETE'), true)) {
            return null;
        }

        $raw = (string) $request->getContent();
        if ($raw === '') {
            return null;
        }

        $json = json_decode($raw, true);
        if (! is_array($json) || count($json) !== 1
            || ! isset($json['__cipher']) || ! is_string($json['__cipher'])) {
            // Not an encrypted envelope — leave the request untouched so plain
            // and encrypted clients can coexist during a rollout.
            return null;
        }

        try {
            $plaintext = $this->bridge->decryptString($json['__cipher'], $keyChain);
        } catch (\Exception $e) {
            return $this->fail(400, 'Could not decrypt request payload.', 'bad_ciphertext');
        }

        $decoded = json_decode($plaintext, true);
        if (! is_array($decoded)) {
            return $this->fail(400, 'Decrypted payload is not a JSON object.', 'bad_payload');
        }

        // Controllers read the decrypted fields via $request->input()/all().
        $request->replace($decoded);
        if ($request->isJson()) {
            $request->json()->replace($decoded);
        }

        return null;
    }

    // -- Outbound: encrypt response ---------------------------------------

    protected function encryptOutbound($response, $keyChain)
    {
        if (! method_exists($response, 'getContent') || ! method_exists($response, 'setContent')) {
            return; // streamed / binary file responses
        }

        $content = $response->getContent();
        if ($content === false || $content === '' || $content === null) {
            return;
        }

        $data = json_decode($content, true);
        if (json_last_error() !== JSON_ERROR_NONE || ! is_array($data)) {
            return; // not JSON — leave as-is
        }

        $mode = $this->bridge->config('response_mode', 'field');

        if ($mode === 'full') {
            $envelope = $this->bridge->encryptString(json_encode($data), $keyChain);
            $response->setContent(json_encode(array('__cipher' => $envelope)));
        } else {
            $key = $this->bridge->config('response_key', 'data');
            if (! array_key_exists($key, $data)) {
                return; // nothing to encrypt
            }
            $data[$key] = $this->bridge->encryptString(json_encode($data[$key]), $keyChain);
            $response->setContent(json_encode($data));
        }

        if (isset($response->headers)) {
            $response->headers->set('Content-Type', 'application/json');
        }
    }

    // -- Helpers -----------------------------------------------------------

    protected function replayGuard()
    {
        if ($this->replayGuard === null) {
            $cache = $this->container->make('cache');
            $store = $this->bridge->config('nonce_store');
            $repo = $store ? $cache->store($store) : $cache->store();
            $this->replayGuard = new ReplayGuard($repo);
        }

        return $this->replayGuard;
    }

    /**
     * Build the JSON error response. Override this method in a subclass to
     * customise the error shape for your API.
     */
    protected function fail($status, $message, $code)
    {
        return response()->json(array(
            'error'        => $message,
            'code'         => $code,
            'secure_bridge' => true,
        ), $status);
    }
}
