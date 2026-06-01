<?php

namespace Irfanokr\SecureBridge\Http\Middleware;

use Closure;
use Irfanokr\SecureBridge\SecureBridge;

/**
 * Emits a strict, nonce-based Content-Security-Policy (optionally with Trusted
 * Types) to *prevent* XSS — the only thing that actually protects a page from
 * injected scripts. Opt-in: enable config('secure-bridge.csp.enabled') and
 * apply the 'secure-bridge.csp' middleware to your web routes.
 *
 * Put the per-request nonce on every <script> via the @cspNonce Blade directive
 * (or SecureBridge::cspNonce()).
 */
class CspMiddleware
{
    const NONCE_BINDING = 'secure-bridge.csp-nonce';

    /** @var SecureBridge */
    protected $bridge;

    public function __construct(SecureBridge $bridge)
    {
        $this->bridge = $bridge;
    }

    public function handle($request, Closure $next)
    {
        if (! $this->bridge->config('csp.enabled')) {
            return $next($request);
        }

        $nonce = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');

        // Expose the nonce to the app (Blade directive / SecureBridge::cspNonce()).
        $request->attributes->set('secure_bridge_csp_nonce', $nonce);
        app()->instance(self::NONCE_BINDING, $nonce);

        $response = $next($request);

        if (! isset($response->headers)) {
            return $response;
        }

        $policy = str_replace('{nonce}', $nonce, (string) $this->bridge->config('csp.policy'));

        if ($this->bridge->config('csp.trusted_types')) {
            $policy .= "; require-trusted-types-for 'script'";
        }

        $reportUri = $this->bridge->config('csp.report_uri');
        if ($reportUri) {
            $policy .= '; report-uri ' . $reportUri;
        }

        $header = $this->bridge->config('csp.report_only')
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        $response->headers->set($header, $policy);

        return $response;
    }
}
