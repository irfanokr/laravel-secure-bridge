<?php

namespace Irfanokr\SecureBridge\Support;

use Illuminate\Http\Request;

/**
 * Builds the canonical string that gets signed, identically on the client and
 * the server.
 *
 *     METHOD \n PATH \n QUERY \n TIMESTAMP \n NONCE \n SHA256-HEX(body)
 *
 * Design notes (these matter for cross-language interop):
 *  - The body is covered by its SHA-256 digest (RFC 9530 style) rather than
 *    inlined, so binary/large bodies and the encrypted envelope are handled
 *    uniformly. The digest is over the RAW bytes on the wire — i.e. AFTER
 *    encryption when encrypt_request is on (encrypt-then-sign).
 *  - PATH and QUERY are taken from the raw request target, NOT re-encoded or
 *    re-sorted, because query-string normalization differs across Laravel /
 *    Symfony versions. The rule is simply "sign exactly what you send, verify
 *    exactly what you receive". The client controls the request, so it signs
 *    the precise path+query it will transmit.
 *  - Empty query pairs and the signature query parameters are stripped on
 *    both sides so signed download links verify.
 */
class Canonicalizer
{
    const EMPTY_BODY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

    /**
     * @param  string[] $stripQueryKeys query keys to remove before signing
     */
    public static function fromRequest(Request $request, $timestamp, $nonce, array $stripQueryKeys = array(), $forceEmptyBody = false)
    {
        $method = strtoupper($request->getMethod());

        list($path, $query) = self::splitTarget($request->getRequestUri());
        $query = self::canonicalQuery($query, $stripQueryKeys);

        if ($forceEmptyBody) {
            // Multipart uploads: the browser controls the serialization/boundary,
            // so both sides sign over an empty body digest.
            $bodyHash = self::EMPTY_BODY_SHA256;
        } else {
            $body = (string) $request->getContent();
            $bodyHash = $body === '' ? self::EMPTY_BODY_SHA256 : hash('sha256', $body);
        }

        return self::build($method, $path, $query, $timestamp, $nonce, $bodyHash);
    }

    public static function build($method, $path, $query, $timestamp, $nonce, $bodyHashHex)
    {
        return $method . "\n"
            . $path . "\n"
            . $query . "\n"
            . $timestamp . "\n"
            . $nonce . "\n"
            . $bodyHashHex;
    }

    /**
     * Split a raw request target ("/a/b?x=1&y=2") into [path, query].
     *
     * @return array{0:string,1:string}
     */
    public static function splitTarget($requestUri)
    {
        $requestUri = (string) $requestUri;
        $pos = strpos($requestUri, '?');
        if ($pos === false) {
            return array($requestUri, '');
        }
        return array(substr($requestUri, 0, $pos), substr($requestUri, $pos + 1));
    }

    /**
     * Remove empty pairs and the given keys, preserving the original byte
     * encoding and order of every kept pair.
     *
     * @param  string[] $stripKeys
     */
    public static function canonicalQuery($queryString, array $stripKeys = array())
    {
        if ($queryString === null || $queryString === '') {
            return '';
        }

        $kept = array();
        foreach (explode('&', $queryString) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq = strpos($pair, '=');
            $key = $eq === false ? $pair : substr($pair, 0, $eq);
            if (in_array($key, $stripKeys, true)) {
                continue;
            }
            $kept[] = $pair;
        }

        return implode('&', $kept);
    }
}
