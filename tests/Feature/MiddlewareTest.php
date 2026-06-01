<?php

namespace Irfanokr\SecureBridge\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Irfanokr\SecureBridge\Drivers\Encryption\AesGcmEncryptionDriver;
use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\Hkdf;
use Irfanokr\SecureBridge\Tests\TestCase;

class MiddlewareTest extends TestCase
{
    protected function defineRoutes($router)
    {
        $router->middleware('secure-bridge')->post('/sb/echo', function (Request $request) {
            return response()->json(array('data' => array('got' => $request->input('msg'))));
        });
    }

    private function signKey()
    {
        return Hkdf::derive($this->master, 32, 'secure-bridge:sign:v1');
    }

    private function encKey()
    {
        return Hkdf::derive($this->master, 32, 'secure-bridge:enc:v1');
    }

    private function sign($method, $uri, $body, $nonce = null)
    {
        $ts = (string) time();
        $nonce = $nonce ?: bin2hex(random_bytes(8));
        list($path, $query) = Canonicalizer::splitTarget($uri);
        $bodyHash = $body === '' ? Canonicalizer::EMPTY_BODY_SHA256 : hash('sha256', $body);
        $canonical = Canonicalizer::build(strtoupper($method), $path, Canonicalizer::canonicalQuery($query), $ts, $nonce, $bodyHash);
        $sig = 'v1=' . (new HmacSignatureDriver())->sign($canonical, $this->signKey());

        return array(
            'CONTENT_TYPE'    => 'application/json',
            'HTTP_X_SIG'       => $sig,
            'HTTP_X_TIMESTAMP' => $ts,
            'HTTP_X_NONCE'     => $nonce,
        );
    }

    public function testValidSignedRequestPasses()
    {
        $body = '{"msg":"hi"}';
        $server = $this->sign('POST', '/sb/echo', $body);

        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);

        $response->assertStatus(200);
        $response->assertJsonPath('data.got', 'hi');
    }

    public function testMissingSignatureIsRejected()
    {
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), array('CONTENT_TYPE' => 'application/json'), '{"msg":"hi"}');

        $response->assertStatus(400);
        $response->assertJsonPath('code', 'missing_signature');
    }

    public function testTamperedBodyIsRejected()
    {
        $server = $this->sign('POST', '/sb/echo', '{"msg":"hi"}');

        // Send a different body than what was signed.
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, '{"msg":"TAMPERED"}');

        $response->assertStatus(400);
        $response->assertJsonPath('code', 'invalid_signature');
    }

    public function testReplayIsRejected()
    {
        $body = '{"msg":"hi"}';
        $server = $this->sign('POST', '/sb/echo', $body, 'fixed-nonce-123');

        $first = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);
        $first->assertStatus(200);

        $second = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);
        $second->assertStatus(409);
        $second->assertJsonPath('code', 'replay');
    }

    public function testStaleTimestampIsRejected()
    {
        $nonce = 'n1';
        $ts = (string) (time() - 100000);
        $body = '{"msg":"hi"}';
        $canonical = Canonicalizer::build('POST', '/sb/echo', '', $ts, $nonce, hash('sha256', $body));
        $sig = 'v1=' . (new HmacSignatureDriver())->sign($canonical, $this->signKey());

        $server = array(
            'CONTENT_TYPE'    => 'application/json',
            'HTTP_X_SIG'       => $sig,
            'HTTP_X_TIMESTAMP' => $ts,
            'HTTP_X_NONCE'     => $nonce,
        );

        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);
        $response->assertStatus(400);
        $response->assertJsonPath('code', 'stale_timestamp');
    }

    public function testEncryptedRequestAndResponseRoundTrip()
    {
        $this->app['config']->set('secure-bridge.encrypt_request', true);
        $this->app['config']->set('secure-bridge.encrypt_response', true);

        $plaintext = '{"msg":"secret-hi"}';
        $envelope = (new AesGcmEncryptionDriver())->encrypt($plaintext, $this->encKey());
        $body = json_encode(array('__cipher' => $envelope));

        $server = $this->sign('POST', '/sb/echo', $body);
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);
        $response->assertStatus(200);

        $json = json_decode($response->getContent(), true);
        $this->assertIsString($json['data'], 'response data should be an encrypted envelope');
        $this->assertStringStartsWith('v1.', $json['data']);

        $decrypted = (new AesGcmEncryptionDriver())->decrypt($json['data'], $this->encKey());
        $this->assertSame(array('got' => 'secret-hi'), json_decode($decrypted, true));
    }

    public function testMultipartRequestStillRequiresSignature()
    {
        // Previously a multipart Content-Type skipped the whole layer; now it
        // must still be signed, so an unsigned multipart request is rejected.
        $server = array('CONTENT_TYPE' => 'multipart/form-data; boundary=X');
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, "--X--\r\n");

        $response->assertStatus(400);
        $response->assertJsonPath('code', 'missing_signature');
    }

    public function testValidSignedMultipartPasses()
    {
        $ts = (string) time();
        $nonce = 'mp-1';
        // Multipart is signed body-less (empty body digest).
        $canonical = Canonicalizer::build('POST', '/sb/echo', '', $ts, $nonce, Canonicalizer::EMPTY_BODY_SHA256);
        $sig = 'v1=' . (new HmacSignatureDriver())->sign($canonical, $this->signKey());

        $server = array(
            'CONTENT_TYPE'     => 'multipart/form-data; boundary=X',
            'HTTP_X_SIG'        => $sig,
            'HTTP_X_TIMESTAMP'  => $ts,
            'HTTP_X_NONCE'      => $nonce,
        );
        $body = "--X\r\nContent-Disposition: form-data; name=\"msg\"\r\n\r\nhi\r\n--X--\r\n";
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, $body);

        $response->assertStatus(200);
    }
}
