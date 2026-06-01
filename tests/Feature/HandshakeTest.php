<?php

namespace Irfanokr\SecureBridge\Tests\Feature;

use Illuminate\Http\Request;
use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\Hkdf;
use Irfanokr\SecureBridge\Tests\TestCase;

class HandshakeTest extends TestCase
{
    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('secure-bridge.key_source', 'token');
        $app['config']->set('secure-bridge.handshake.enabled', true);
        $app['config']->set('secure-bridge.handshake.middleware', array()); // open for the test
        $app['config']->set('secure-bridge.handshake.route', 'secure-bridge/handshake');
    }

    protected function defineRoutes($router)
    {
        $router->middleware('secure-bridge')->post('/sb/echo', function (Request $request) {
            return response()->json(array('data' => array('got' => $request->input('msg'))));
        });
    }

    public function testSignedRequestWithoutHandshakeRequiresHandshake()
    {
        $server = array('CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer tkn-abc');
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, '{"msg":"hi"}');

        $response->assertStatus(412);
        $response->assertJsonPath('code', 'handshake_required');
    }

    public function testHandshakeIssuesKeyThenSignedRequestPasses()
    {
        // 1. Handshake (authenticated by the bearer token) returns a per-session key.
        $handshake = $this->call('POST', 'secure-bridge/handshake', array(), array(), array(), array('HTTP_AUTHORIZATION' => 'Bearer tkn-abc'));
        $handshake->assertStatus(200);
        $payload = json_decode($handshake->getContent(), true);
        $this->assertNotEmpty($payload['key']);

        // 2. Derive the signing sub-key exactly as the client would.
        $master = base64_decode($payload['key']);
        $signKey = Hkdf::derive($master, 32, 'secure-bridge:sign:v1');

        // 3. Sign a request with the SAME bearer token and send it.
        $body = '{"msg":"hi"}';
        $ts = (string) time();
        $nonce = 'nonce-xyz';
        $canonical = Canonicalizer::build('POST', '/sb/echo', '', $ts, $nonce, hash('sha256', $body));
        $sig = 'v1=' . (new HmacSignatureDriver())->sign($canonical, $signKey);

        $server = array(
            'CONTENT_TYPE'     => 'application/json',
            'HTTP_AUTHORIZATION' => 'Bearer tkn-abc',
            'HTTP_X_SIG'        => $sig,
            'HTTP_X_TIMESTAMP'  => $ts,
            'HTTP_X_NONCE'      => $nonce,
        );
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);

        $response->assertStatus(200);
        $response->assertJsonPath('data.got', 'hi');
    }

    public function testKeyIsBoundToTheToken()
    {
        // Issue a key for token A.
        $handshake = $this->call('POST', 'secure-bridge/handshake', array(), array(), array(), array('HTTP_AUTHORIZATION' => 'Bearer token-A'));
        $payload = json_decode($handshake->getContent(), true);
        $signKey = Hkdf::derive(base64_decode($payload['key']), 32, 'secure-bridge:sign:v1');

        // Sign with A's key but present token B -> different (or missing) key -> rejected.
        $body = '{"msg":"hi"}';
        $ts = (string) time();
        $nonce = 'n-2';
        $canonical = Canonicalizer::build('POST', '/sb/echo', '', $ts, $nonce, hash('sha256', $body));
        $sig = 'v1=' . (new HmacSignatureDriver())->sign($canonical, $signKey);

        $server = array(
            'CONTENT_TYPE'     => 'application/json',
            'HTTP_AUTHORIZATION' => 'Bearer token-B',
            'HTTP_X_SIG'        => $sig,
            'HTTP_X_TIMESTAMP'  => $ts,
            'HTTP_X_NONCE'      => $nonce,
        );
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);

        // token-B has no issued key yet -> handshake required.
        $response->assertStatus(412);
        $response->assertJsonPath('code', 'handshake_required');
    }
}
