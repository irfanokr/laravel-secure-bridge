<?php

namespace Irfanokr\SecureBridge\Http;

use Illuminate\Http\Request;
use Irfanokr\SecureBridge\SecureBridge;

/**
 * Issues a per-session signing/encryption key to an already-authenticated SPA.
 *
 * Mounted at config('secure-bridge.handshake.route') behind your own auth
 * middleware (config('secure-bridge.handshake.middleware')). The client calls
 * this once after login and keeps the returned key IN MEMORY ONLY.
 */
class HandshakeController
{
    public function __invoke(Request $request, SecureBridge $bridge)
    {
        $payload = $bridge->handshakePayload($request);

        if ($payload === null || $payload['key'] === null) {
            return response()->json(array(
                'error' => 'Unauthenticated — cannot issue a SecureBridge key.',
                'code'  => 'unauthenticated',
            ), 401);
        }

        return response()->json($payload);
    }
}
