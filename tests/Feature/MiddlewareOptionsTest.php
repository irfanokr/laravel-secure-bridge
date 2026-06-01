<?php

namespace Irfanokr\SecureBridge\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Irfanokr\SecureBridge\Drivers\Encryption\AesGcmEncryptionDriver;
use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Events\RequestBlocked;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\Hkdf;
use Irfanokr\SecureBridge\Tests\TestCase;

class MiddlewareOptionsTest extends TestCase
{
    private function signKey()
    {
        return Hkdf::derive($this->master, 32, 'secure-bridge:sign:v1');
    }

    private function encKey()
    {
        return Hkdf::derive($this->master, 32, 'secure-bridge:enc:v1');
    }

    private function sign($method, $uri, $body)
    {
        $ts = (string) time();
        $nonce = bin2hex(random_bytes(8));
        list($path, $query) = Canonicalizer::splitTarget($uri);
        $bodyHash = $body === '' ? Canonicalizer::EMPTY_BODY_SHA256 : hash('sha256', $body);
        $canonical = Canonicalizer::build(strtoupper($method), $path, Canonicalizer::canonicalQuery($query), $ts, $nonce, $bodyHash);

        return array(
            'CONTENT_TYPE'     => 'application/json',
            'HTTP_X_SIG'        => 'v1=' . (new HmacSignatureDriver())->sign($canonical, $this->signKey()),
            'HTTP_X_TIMESTAMP'  => $ts,
            'HTTP_X_NONCE'      => $nonce,
        );
    }

    protected function defineRoutes($router)
    {
        // encrypt-response only: no signature required, response is encrypted.
        $router->middleware('secure-bridge:encrypt-response')->get('/sb/open', function () {
            return response()->json(array('data' => array('v' => 1)));
        });

        // sign only: signature required, response NOT encrypted.
        $router->middleware('secure-bridge:sign')->post('/sb/signonly', function (Request $request) {
            return response()->json(array('data' => array('got' => $request->input('msg'))));
        });
    }

    public function testEncryptResponseOnlyRouteSkipsSigningAndEncryptsResponse()
    {
        $response = $this->get('/sb/open'); // unsigned — allowed because 'sign' is off
        $response->assertStatus(200);

        $json = json_decode($response->getContent(), true);
        $this->assertIsString($json['data']);
        $this->assertStringStartsWith('v1.', $json['data']);

        $decrypted = (new AesGcmEncryptionDriver())->decrypt($json['data'], $this->encKey());
        $this->assertSame(array('v' => 1), json_decode($decrypted, true));
    }

    public function testSignOnlyRouteRequiresSignatureAndLeavesResponsePlaintext()
    {
        $unsigned = $this->call('POST', '/sb/signonly', array(), array(), array(), array('CONTENT_TYPE' => 'application/json'), '{"msg":"hi"}');
        $unsigned->assertStatus(400);
        $unsigned->assertJsonPath('code', 'missing_signature');

        $body = '{"msg":"hi"}';
        $signed = $this->call('POST', '/sb/signonly', array(), array(), array(), $this->sign('POST', '/sb/signonly', $body), $body);
        $signed->assertStatus(200);
        $signed->assertJsonPath('data.got', 'hi'); // plaintext, response not encrypted
    }

    public function testRequestBlockedEventIsDispatched()
    {
        $captured = array();
        Event::listen(RequestBlocked::class, function ($e) use (&$captured) {
            $captured[] = $e;
        });

        $this->call('POST', '/sb/signonly', array(), array(), array(), array('CONTENT_TYPE' => 'application/json'), '{"msg":"hi"}');

        $this->assertNotEmpty($captured);
        $this->assertSame('missing_signature', $captured[0]->code);
        $this->assertSame(400, $captured[0]->status);
    }
}
