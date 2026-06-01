<?php

namespace Irfanokr\SecureBridge\Tests\Feature;

use Illuminate\Http\Request;
use Irfanokr\SecureBridge\Tests\TestCase;

class EcdsaHandshakeTest extends TestCase
{
    // A valid P-256 SPKI public key (from the frozen interop vector).
    private $spki = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7X3JdnvbdFHhfgBB8XFOjKJ/BuUT3YL7Mz0HQrO84Cg0kceKeKpNhEBzBP8yHCDO6N1SuTRlgxzEQvSaHzPpzg==';

    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('secure-bridge.key_source', 'token');
        $app['config']->set('secure-bridge.signature_driver', 'ecdsa');
        $app['config']->set('secure-bridge.handshake.enabled', true);
        $app['config']->set('secure-bridge.handshake.middleware', array());
        $app['config']->set('secure-bridge.handshake.route', 'secure-bridge/handshake');
    }

    protected function defineRoutes($router)
    {
        $router->middleware('secure-bridge')->post('/sb/echo', function (Request $request) {
            return response()->json(array('data' => array('got' => $request->input('msg'))));
        });
    }

    public function testEcdsaWithoutHandshakeRequiresHandshake()
    {
        $server = array('CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer t-1');
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, '{"msg":"hi"}');

        $response->assertStatus(412);
        $response->assertJsonPath('code', 'handshake_required');
    }

    public function testHandshakeRequiresPublicKey()
    {
        $server = array('CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer t-1');
        $response = $this->call('POST', 'secure-bridge/handshake', array(), array(), array(), $server, '{}');

        $response->assertStatus(400);
        $response->assertJsonPath('code', 'missing_public_key');
    }

    public function testHandshakeStoresPublicKeyAndSignatureIsThenVerified()
    {
        $server = array('CONTENT_TYPE' => 'application/json', 'HTTP_AUTHORIZATION' => 'Bearer t-1');
        $handshake = $this->call('POST', 'secure-bridge/handshake', array(), array(), array(), $server, json_encode(array('publicKey' => $this->spki)));

        $handshake->assertStatus(200);
        $handshake->assertJsonPath('signatureDriver', 'ecdsa');
        $payload = json_decode($handshake->getContent(), true);
        $this->assertNull($payload['key'], 'no symmetric key is returned when encryption is off');

        // Public key is now registered, so readiness passes; a bogus signature
        // must fail verification (400 invalid_signature, NOT 412).
        $bogus = array(
            'CONTENT_TYPE'     => 'application/json',
            'HTTP_AUTHORIZATION' => 'Bearer t-1',
            'HTTP_X_SIG'        => 'v1=AAAAAAAA',
            'HTTP_X_TIMESTAMP'  => (string) time(),
            'HTTP_X_NONCE'      => 'n-1',
        );
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $bogus, '{"msg":"hi"}');

        $response->assertStatus(400);
        $response->assertJsonPath('code', 'invalid_signature');
    }
}
