<?php

namespace Irfanokr\SecureBridge\Events;

use Illuminate\Http\Request;

/**
 * Dispatched whenever SecureBridge rejects a request (bad/missing signature,
 * stale timestamp, replay, decryption failure, handshake required, insecure
 * transport). Listen for it to log or alert — it carries NO request payload,
 * only metadata, so it is safe to log.
 *
 *   Event::listen(RequestBlocked::class, function ($e) {
 *       Log::warning('SecureBridge blocked', [
 *           'code' => $e->code, 'status' => $e->status,
 *           'ip' => $e->request->ip(), 'path' => $e->request->path(),
 *       ]);
 *   });
 */
class RequestBlocked
{
    /** @var Request */
    public $request;

    /** @var int HTTP status returned */
    public $status;

    /** @var string machine code, e.g. invalid_signature / replay / stale_timestamp */
    public $code;

    /** @var string human-readable reason */
    public $message;

    public function __construct(Request $request, $status, $code, $message)
    {
        $this->request = $request;
        $this->status = $status;
        $this->code = $code;
        $this->message = $message;
    }
}
