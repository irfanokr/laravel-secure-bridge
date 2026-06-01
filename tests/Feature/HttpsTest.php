<?php

namespace Irfanokr\SecureBridge\Tests\Feature;

use Illuminate\Http\Request;
use Irfanokr\SecureBridge\Tests\TestCase;

class HttpsTest extends TestCase
{
    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('secure-bridge.require_https', true);
    }

    protected function defineRoutes($router)
    {
        $router->middleware('secure-bridge')->post('/sb/echo', function (Request $request) {
            return response()->json(array('data' => array('got' => $request->input('msg'))));
        });
    }

    public function testInsecureRemoteRequestIsRejected()
    {
        // Absolute non-local http URL so getHost() is a real remote host.
        $server = array('CONTENT_TYPE' => 'application/json');
        $response = $this->call('POST', 'http://example.com/sb/echo', array(), array(), array(), $server, '{"msg":"hi"}');

        $response->assertStatus(400);
        $response->assertJsonPath('code', 'insecure_transport');
    }

    public function testLocalhostPassesTheHttpsGate()
    {
        // Default host is localhost -> allowed through the HTTPS gate, so it
        // proceeds and fails later for the missing signature instead.
        $server = array('CONTENT_TYPE' => 'application/json');
        $response = $this->call('POST', '/sb/echo', array(), array(), array(), $server, '{"msg":"hi"}');

        $response->assertJsonPath('code', 'missing_signature');
    }
}
