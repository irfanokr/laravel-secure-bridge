<?php

namespace Irfanokr\SecureBridge\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\Hkdf;
use Irfanokr\SecureBridge\Tests\TestCase;

/**
 * Setup A — "Laravel + Blade". Proves the per-session key path used by the
 * @secureBridge directive: the key the server hands the page (clientConfig) is
 * the same per-session key the middleware verifies against (keyChainForRequest),
 * it is NOT the static bundle key, and it is stable per session.
 */
class SessionKeyTest extends TestCase
{
    private function requestWithSession()
    {
        $request = Request::create('/dashboard', 'GET');
        $session = new Store('sb_test', new ArraySessionHandler(120));
        $session->start();
        $request->setLaravelSession($session);

        return $request;
    }

    public function testBladeSessionKeyRoundTrip()
    {
        $this->app['config']->set('secure-bridge.session_key.enabled', true);
        $bridge = $this->app->make('secure-bridge');

        $request = $this->requestWithSession();

        // 1) What @secureBridge hands the JavaScript on the page.
        $cfg = $bridge->clientConfig($request);
        $clientKeyB64 = $cfg['key'];
        $this->assertNotEmpty($clientKeyB64);

        // It must be a fresh per-session key, not the static bundle key.
        $this->assertNotSame(base64_encode($this->master), $clientKeyB64);

        // 2) The browser signs a request with that key.
        $signKey = Hkdf::derive(base64_decode($clientKeyB64), 32, 'secure-bridge:sign:v1');
        $ts = (string) time();
        $nonce = 'sess-nonce-1';
        $body = '{"msg":"hi"}';
        $canonical = Canonicalizer::build('POST', '/sb/save', '', $ts, $nonce, hash('sha256', $body));
        $sig = 'v1=' . (new HmacSignatureDriver())->sign($canonical, $signKey);

        // 3) The server resolves the SAME per-session key chain and accepts it.
        $keyChain = $bridge->keyChainForRequest($request);
        $this->assertTrue(
            $bridge->verifyCanonical($canonical, $sig, $keyChain),
            'server should verify a request signed with the per-session key'
        );

        // 4) A signature made with the static bundle key must be rejected here.
        $staticSig = 'v1=' . (new HmacSignatureDriver())->sign(
            $canonical,
            Hkdf::derive($this->master, 32, 'secure-bridge:sign:v1')
        );
        $this->assertFalse(
            $bridge->verifyCanonical($canonical, $staticSig, $keyChain),
            'the static bundle key must not work in per-session mode'
        );
    }

    public function testSessionKeyIsStableWithinASessionAndUniquePerSession()
    {
        $this->app['config']->set('secure-bridge.session_key.enabled', true);
        $bridge = $this->app->make('secure-bridge');

        $request = $this->requestWithSession();
        $first = $bridge->clientConfig($request)['key'];
        $again = $bridge->clientConfig($request)['key'];
        $this->assertSame($first, $again, 'the key is stable within one session');

        $other = $bridge->clientConfig($this->requestWithSession())['key'];
        $this->assertNotSame($first, $other, 'a different session gets a different key');
    }
}
