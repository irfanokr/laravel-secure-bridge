/*!
 * secure-bridge-client — framework-agnostic client for irfanokr/laravel-secure-bridge.
 *
 * Implements the v1 wire format (HMAC-SHA256 request signing + AES-256-GCM
 * payload encryption) using the Web Crypto API. Works in any modern browser
 * and in Node 18+ (for testing). No dependencies.
 *
 * Wire format (must match the Laravel side byte-for-byte):
 *   - keys     : signKey = HKDF-SHA256(master, info="secure-bridge:sign:v1", 32)
 *                encKey  = HKDF-SHA256(master, info="secure-bridge:enc:v1",  32)
 *   - canonical: METHOD \n PATH \n QUERY \n TS \n NONCE \n sha256hex(body)
 *   - signature: "v1=" + hmac_sha256_hex(signKey, canonical)
 *   - envelope : "v1." + base64(iv[12]) + "." + base64(ciphertext||tag[16])
 *                with AES-256-GCM, AAD = "secure-bridge:v1"
 *
 * MIT License.
 */
(function (root, factory) {
    if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else {
        root.SecureBridge = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ---- environment helpers --------------------------------------------

    function getCrypto() {
        var c = (typeof globalThis !== 'undefined' && globalThis.crypto) ? globalThis.crypto
            : (typeof window !== 'undefined' && window.crypto) ? window.crypto
            : (typeof self !== 'undefined' && self.crypto) ? self.crypto
            : null;
        if (!c || !c.subtle) {
            throw new Error('SecureBridge: Web Crypto (crypto.subtle) is not available. '
                + 'A secure context (HTTPS or localhost) is required in browsers.');
        }
        return c;
    }

    var _enc = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;
    var _dec = (typeof TextDecoder !== 'undefined') ? new TextDecoder() : null;

    function utf8(str) {
        if (_enc) { return _enc.encode(str); }
        // minimal fallback
        return new Uint8Array(Buffer.from(str, 'utf8'));
    }

    function fromUtf8(bytes) {
        if (_dec) { return _dec.decode(bytes); }
        return Buffer.from(bytes).toString('utf8');
    }

    function bytesToB64(bytes) {
        if (typeof btoa === 'function') {
            var bin = '';
            for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
            return btoa(bin);
        }
        return Buffer.from(bytes).toString('base64');
    }

    function b64ToBytes(b64) {
        if (typeof atob === 'function') {
            var bin = atob(b64);
            var out = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
            return out;
        }
        return new Uint8Array(Buffer.from(b64, 'base64'));
    }

    function bufToHex(buf) {
        var b = new Uint8Array(buf);
        var h = '';
        for (var i = 0; i < b.length; i++) {
            var x = b[i].toString(16);
            h += x.length === 1 ? '0' + x : x;
        }
        return h;
    }

    function randomBytes(n) {
        var out = new Uint8Array(n);
        getCrypto().getRandomValues(out);
        return out;
    }

    // True only for the engine's built-in function (not a user/polyfill wrapper).
    function isNativeFn(fn) {
        try { return /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn)); }
        catch (e) { return false; }
    }

    // ---- primitives ------------------------------------------------------

    var AAD = 'secure-bridge:v1';

    function hkdf(masterBytes, infoStr, length) {
        var subtle = getCrypto().subtle;
        return subtle.importKey('raw', masterBytes, 'HKDF', false, ['deriveBits']).then(function (base) {
            return subtle.deriveBits(
                { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(infoStr) },
                base,
                length * 8
            );
        }).then(function (bits) {
            return new Uint8Array(bits);
        });
    }

    function sha256Hex(str) {
        return getCrypto().subtle.digest('SHA-256', utf8(str)).then(bufToHex);
    }

    function hmacHex(keyBytes, msgStr) {
        var subtle = getCrypto().subtle;
        return subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']).then(function (key) {
            return subtle.sign('HMAC', key, utf8(msgStr));
        }).then(bufToHex);
    }

    function aesGcmEncrypt(keyBytes, plaintextStr) {
        var subtle = getCrypto().subtle;
        var iv = randomBytes(12);
        return subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']).then(function (key) {
            return subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: utf8(AAD), tagLength: 128 }, key, utf8(plaintextStr));
        }).then(function (ctBuf) {
            return 'v1.' + bytesToB64(iv) + '.' + bytesToB64(new Uint8Array(ctBuf));
        });
    }

    function aesGcmDecrypt(keyBytes, envelope) {
        var parts = String(envelope).split('.');
        if (parts.length !== 3 || parts[0] !== 'v1') {
            return Promise.reject(new Error('SecureBridge: malformed ciphertext envelope'));
        }
        var iv = b64ToBytes(parts[1]);
        var blob = b64ToBytes(parts[2]);
        var subtle = getCrypto().subtle;
        return subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']).then(function (key) {
            return subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: utf8(AAD), tagLength: 128 }, key, blob);
        }).then(function (ptBuf) {
            return fromUtf8(new Uint8Array(ptBuf));
        });
    }

    // ---- canonicalization ------------------------------------------------

    function splitUrl(url) {
        var hashless = String(url).split('#')[0];
        var qi = hashless.indexOf('?');
        var pathPart = qi === -1 ? hashless : hashless.slice(0, qi);
        var query = qi === -1 ? '' : hashless.slice(qi + 1);
        var m = pathPart.match(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/[^\/]+(\/[\s\S]*)?$/);
        if (m) {
            pathPart = (m[1] !== undefined && m[1] !== '') ? m[1] : '/';
        } else if (pathPart === '') {
            pathPart = '/';
        }
        return { path: pathPart, query: query };
    }

    function dropEmptyPairs(query, stripKeys) {
        if (!query) { return ''; }
        stripKeys = stripKeys || [];
        var pairs = query.split('&');
        var kept = [];
        for (var i = 0; i < pairs.length; i++) {
            var p = pairs[i];
            if (p === '') { continue; }
            var eq = p.indexOf('=');
            var k = eq === -1 ? p : p.slice(0, eq);
            if (stripKeys.indexOf(k) !== -1) { continue; }
            kept.push(p);
        }
        return kept.join('&');
    }

    function buildCanonical(method, path, query, ts, nonce, bodyHashHex) {
        return method + '\n' + path + '\n' + query + '\n' + ts + '\n' + nonce + '\n' + bodyHashHex;
    }

    function makeNonce() {
        return bufToHex(randomBytes(16));
    }

    // ---- object helpers --------------------------------------------------

    function assign(target) {
        for (var i = 1; i < arguments.length; i++) {
            var s = arguments[i];
            if (s) {
                for (var k in s) {
                    if (Object.prototype.hasOwnProperty.call(s, k)) { target[k] = s[k]; }
                }
            }
        }
        return target;
    }

    function headersToObject(h) {
        var o = {};
        if (!h) { return o; }
        if (typeof Headers !== 'undefined' && h instanceof Headers) {
            h.forEach(function (v, k) { o[k] = v; });
            return o;
        }
        if (Array.isArray(h)) {
            for (var i = 0; i < h.length; i++) { o[h[i][0]] = h[i][1]; }
            return o;
        }
        return assign({}, h);
    }

    function normalizeConfig(c) {
        c = c || {};
        return {
            key: c.key,
            signatureDriver: c.signatureDriver || 'hmac',
            sign: c.sign !== false,
            encryptRequest: !!c.encryptRequest,
            encryptResponse: !!c.encryptResponse,
            responseMode: c.responseMode || 'field',
            responseKey: c.responseKey || 'data',
            window: c.window || 300,
            expiresIn: (typeof c.expiresIn === 'number' && c.expiresIn > 0) ? c.expiresIn : 3600,
            headers: c.headers || { signature: 'X-Sig', timestamp: 'X-Timestamp', nonce: 'X-Nonce' },
            query: c.query || { signature: '__sb_sig', timestamp: '__sb_ts', nonce: '__sb_nonce' }
        };
    }

    var WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    // ---- client ----------------------------------------------------------

    function SecureBridgeClient(config) {
        this.config = normalizeConfig(config);
        this._keys = null;
        this._signMode = this.config.signatureDriver === 'ecdsa' ? 'ecdsa' : 'hmac';
        this._privateKey = null; // non-extractable ECDSA CryptoKey, set by handshake()
    }

    SecureBridgeClient.prototype._derive = function () {
        if (this._keys) { return this._keys; }
        if (!this.config.key) {
            return Promise.reject(new Error('SecureBridge: no key configured. Call configure({ key: "<base64>" }).'));
        }
        var master = b64ToBytes(this.config.key);
        this._keys = Promise.all([
            hkdf(master, 'secure-bridge:sign:v1', 32),
            hkdf(master, 'secure-bridge:enc:v1', 32)
        ]).then(function (arr) {
            return { sign: arr[0], enc: arr[1] };
        });
        return this._keys;
    };

    /**
     * Encrypt + sign a request. Resolves to { url, method, headers, body }.
     */
    SecureBridgeClient.prototype.prepare = function (method, url, body) {
        var self = this;
        var cfg = this.config;
        method = (method || 'GET').toUpperCase();

        var isEcdsa = self._signMode === 'ecdsa' && self._privateKey;
        var hasBody = body !== undefined && body !== null && WRITE_METHODS.indexOf(method) !== -1;
        var isForm = hasBody && (typeof FormData !== 'undefined' && body instanceof FormData);
        var isUrlEnc = hasBody && (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams);
        var isBinary = hasBody && (
            (typeof Blob !== 'undefined' && body instanceof Blob)
            || (typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer)
            || (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView && ArrayBuffer.isView(body))
        );
        // Multipart / binary bodies are sent as-is and never encrypted.
        var needEnc = hasBody && cfg.encryptRequest && !isForm && !isUrlEnc && !isBinary;
        var needSym = needEnc || (cfg.sign && !isEcdsa);

        var keysPromise = needSym ? self._derive() : Promise.resolve(null);

        return keysPromise.then(function (keys) {
            var headers = {};
            var sendBody;            // what we actually transmit
            var hashStringPromise;   // string to hash for the canonical ('' = body-less)

            if (!hasBody) {
                sendBody = undefined;
                hashStringPromise = Promise.resolve('');
            } else if (isForm || isBinary) {
                // The browser/library owns these bodies (multipart boundary or
                // raw bytes); send them unchanged and sign body-less (the server
                // matches with an empty body digest). Never JSON.stringify them.
                sendBody = body;
                hashStringPromise = Promise.resolve('');
            } else if (isUrlEnc) {
                sendBody = body.toString();
                headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
                hashStringPromise = Promise.resolve(sendBody);
            } else {
                var plaintext = (typeof body === 'string') ? body : JSON.stringify(body);
                headers['Content-Type'] = 'application/json';
                if (needEnc) {
                    hashStringPromise = aesGcmEncrypt(keys.enc, plaintext).then(function (env) {
                        sendBody = JSON.stringify({ __cipher: env });
                        return sendBody;
                    });
                } else {
                    sendBody = plaintext;
                    hashStringPromise = Promise.resolve(plaintext);
                }
            }

            return hashStringPromise.then(function (hashString) {
                if (!cfg.sign) {
                    return { url: url, method: method, headers: headers, body: hasBody ? sendBody : undefined };
                }
                var ts = Math.floor(Date.now() / 1000).toString();
                var nonce = makeNonce();
                var parts = splitUrl(url);
                var query = dropEmptyPairs(parts.query, []);
                return sha256Hex(hashString).then(function (bodyHash) {
                    var canonical = buildCanonical(method, parts.path, query, ts, nonce, bodyHash);
                    var sigPromise = isEcdsa
                        ? getCrypto().subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, self._privateKey, utf8(canonical))
                            .then(function (buf) { return 'v1=' + bytesToB64(new Uint8Array(buf)); })
                        : hmacHex(keys.sign, canonical).then(function (mac) { return 'v1=' + mac; });
                    return sigPromise.then(function (sigVal) {
                        headers[cfg.headers.signature] = sigVal;
                        headers[cfg.headers.timestamp] = ts;
                        headers[cfg.headers.nonce] = nonce;
                        return { url: url, method: method, headers: headers, body: hasBody ? sendBody : undefined };
                    });
                });
            });
        });
    };

    /**
     * Append signature query parameters to a GET URL (downloads / window.open).
     */
    SecureBridgeClient.prototype.signUrl = function (url) {
        var self = this;
        var cfg = this.config;
        if (!cfg.sign) { return Promise.resolve(url); }
        var isEcdsa = self._signMode === 'ecdsa' && self._privateKey;
        var keysPromise = isEcdsa ? Promise.resolve(null) : self._derive();
        return keysPromise.then(function (keys) {
            var ts = Math.floor(Date.now() / 1000).toString();
            var nonce = makeNonce();
            var parts = splitUrl(url);
            var stripKeys = [cfg.query.signature, cfg.query.timestamp, cfg.query.nonce];
            var query = dropEmptyPairs(parts.query, stripKeys);
            return sha256Hex('').then(function (bodyHash) {
                var canonical = buildCanonical('GET', parts.path, query, ts, nonce, bodyHash);
                var macPromise = isEcdsa
                    ? getCrypto().subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, self._privateKey, utf8(canonical))
                        .then(function (buf) { return bytesToB64(new Uint8Array(buf)); })
                    : hmacHex(keys.sign, canonical);
                return macPromise.then(function (mac) {
                    var sep = url.indexOf('?') === -1 ? '?' : '&';
                    return url + sep
                        + cfg.query.signature + '=' + encodeURIComponent('v1=' + mac)
                        + '&' + cfg.query.timestamp + '=' + ts
                        + '&' + cfg.query.nonce + '=' + nonce;
                });
            });
        });
    };

    SecureBridgeClient.prototype.encryptPayload = function (obj) {
        return this._derive().then(function (keys) {
            return aesGcmEncrypt(keys.enc, typeof obj === 'string' ? obj : JSON.stringify(obj));
        });
    };

    SecureBridgeClient.prototype.decryptEnvelope = function (envelope) {
        return this._derive().then(function (keys) {
            return aesGcmDecrypt(keys.enc, envelope).then(function (plain) { return JSON.parse(plain); });
        });
    };

    /**
     * Decrypt the data field (or whole body) of a parsed JSON response object.
     */
    SecureBridgeClient.prototype.processResponse = function (obj) {
        var cfg = this.config;
        if (!obj || typeof obj !== 'object') { return Promise.resolve(obj); }

        return this._derive().then(function (keys) {
            if (typeof obj.__cipher === 'string') {
                return aesGcmDecrypt(keys.enc, obj.__cipher).then(function (plain) { return JSON.parse(plain); });
            }
            if (cfg.responseMode === 'field') {
                var k = cfg.responseKey;
                if (Object.prototype.hasOwnProperty.call(obj, k)
                    && typeof obj[k] === 'string' && obj[k].indexOf('v1.') === 0) {
                    return aesGcmDecrypt(keys.enc, obj[k]).then(function (plain) {
                        obj[k] = JSON.parse(plain);
                        return obj;
                    });
                }
            }
            return obj;
        });
    };

    // ---- singleton + auto-wiring ----------------------------------------

    var _default = null;

    function configure(config) {
        _default = new SecureBridgeClient(config);
        return _default;
    }

    function instance() {
        if (!_default) {
            throw new Error('SecureBridge: call SecureBridge.configure({ key: "<base64>" }) first.');
        }
        return _default;
    }

    // ---- auto-mode: SecureBridge.start({ handshake, token }) -------------
    // A single call at app startup. The first request that carries a token
    // triggers the handshake; the issued per-session key is reused until it
    // nears expiry or the token changes, then fetched again — so there is no
    // login wiring, no reload wiring, and no 412 handling for the app to do.
    var _auto = null;            // { handshakeUrl, tokenGetter, onError, handshakeInit, refreshMargin }
    var _autoExpiresAt = 0;      // epoch ms at which the current key should be renewed
    var _autoTokenUsed = null;   // the token the current key is bound to
    var _autoInflight = null;    // shared in-flight handshake (dedupes concurrent first requests)

    function resolveToken() {
        if (!_auto) { return null; }
        var t = _auto.tokenGetter;
        var v;
        try { v = (typeof t === 'function') ? t() : t; } catch (e) { return null; }
        if (v === null || v === undefined || v === '') { return null; }
        return (typeof v === 'string') ? v : String(v);
    }

    // Resolves true => sign this request; false => send it unsigned.
    // NEVER rejects — a handshake failure falls back to sending unsigned.
    function ensureKey() {
        if (!_auto) {
            // legacy / manual mode: sign only if a key is already configured.
            return Promise.resolve(!!_default);
        }
        var token = resolveToken();
        // No token yet (e.g. before login): do not handshake; send unsigned so
        // public and login routes keep working.
        if (token === null) { return Promise.resolve(false); }

        var fresh = _default && _default.config && _default.config.key
            && _autoTokenUsed === token && Date.now() < _autoExpiresAt;
        if (fresh) { return Promise.resolve(true); }

        if (_autoInflight) { return _autoInflight; }

        var margin = (typeof _auto.refreshMargin === 'number') ? _auto.refreshMargin : 30000;
        var hsInit = assign({}, _auto.handshakeInit || {});
        hsInit.headers = assign({ Authorization: 'Bearer ' + token }, headersToObject(hsInit.headers));

        _autoInflight = handshake(_auto.handshakeUrl, hsInit).then(function (client) {
            var secs = (client && client.config && typeof client.config.expiresIn === 'number'
                && client.config.expiresIn > 0) ? client.config.expiresIn : 3600;
            var life = secs * 1000;
            // Use at least half the key's lifetime even if the margin is large.
            _autoExpiresAt = Date.now() + Math.max(life - margin, Math.floor(life / 2));
            _autoTokenUsed = token;
            _autoInflight = null;
            return true;
        }, function (err) {
            _autoInflight = null;
            _autoExpiresAt = 0;
            _autoTokenUsed = null;
            if (_auto && typeof _auto.onError === 'function') {
                try { _auto.onError(err); } catch (e) {}
            }
            return false; // proceed unsigned; never throw into the app's request
        });
        return _autoInflight;
    }

    function isSameOrigin(url) {
        try {
            if (/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//.test(url)) {
                if (typeof location === 'undefined') { return true; }
                return url.indexOf(location.origin) === 0;
            }
            return true; // relative URL
        } catch (e) {
            return true;
        }
    }

    function installFetch(target) {
        var g = target || (typeof window !== 'undefined' ? window
            : (typeof globalThis !== 'undefined' ? globalThis : self));
        if (!g.fetch || g.__secureBridgeFetch) { return; }
        var orig = g.fetch.bind(g);
        g.__secureBridgeFetch = orig;

        g.fetch = function (input, init) {
            init = init || {};
            var url = typeof input === 'string' ? input : (input && input.url);
            var method = init.method || (typeof input !== 'string' && input && input.method) || 'GET';
            if (!isSameOrigin(url)) { return orig(input, init); }

            function decrypt(client, resp) {
                if (!client.config.encryptResponse) { return resp; }
                var ct = (resp.headers && resp.headers.get) ? (resp.headers.get('content-type') || '') : '';
                if (ct.indexOf('application/json') === -1) { return resp; }
                return resp.clone().text().then(function (text) {
                    try {
                        var obj = JSON.parse(text);
                        return client.processResponse(obj).then(function (processed) {
                            return new Response(JSON.stringify(processed), {
                                status: resp.status,
                                statusText: resp.statusText,
                                headers: resp.headers
                            });
                        });
                    } catch (e) {
                        return resp;
                    }
                });
            }

            function signOnce() {
                var client = instance();
                return client.prepare(method, url, init.body).then(function (p) {
                    var merged = assign(headersToObject(init.headers), p.headers);
                    var newInit = assign({}, init, { method: p.method, headers: merged });
                    if (p.body !== undefined) { newInit.body = p.body; }
                    return orig(p.url, newInit).then(function (resp) { return { client: client, resp: resp }; });
                });
            }

            // Legacy / manual mode — unchanged behaviour (throws if not configured).
            if (!_auto) {
                return signOnce().then(function (r) { return decrypt(r.client, r.resp); });
            }

            // Auto mode: a request body is replayable for the 412 retry unless it
            // is a stream or an already-consumed Request.
            function bodyReplayable() {
                var b = init.body;
                if (b === undefined || b === null) { return true; }
                if (typeof ReadableStream !== 'undefined' && b instanceof ReadableStream) { return false; }
                if (typeof input !== 'string' && input && input.bodyUsed) { return false; }
                return true;
            }

            return ensureKey().then(function (signed) {
                if (!signed) { return orig(input, init); }   // no token / handshake failed → unsigned
                return signOnce().then(function (r) {
                    if (r.resp && r.resp.status === 412 && bodyReplayable()) {
                        _autoExpiresAt = 0; _autoTokenUsed = null;      // invalidate, force re-handshake
                        return ensureKey().then(function (ok2) {
                            if (!ok2) { return r.resp; }
                            return signOnce().then(function (r2) { return decrypt(r2.client, r2.resp); });
                        });
                    }
                    return decrypt(r.client, r.resp);
                }, function () {
                    return orig(input, init);   // signing failed (no key) → send unsigned
                });
            });
        };
    }

    /**
     * Transparently sign EVERY XMLHttpRequest. Because axios and jQuery both use
     * XMLHttpRequest under the hood in the browser, this one patch covers raw
     * XHR, axios and jQuery at once — existing request code is never changed.
     *
     * Signing is async (Web Crypto); XHR's send() is not. We simply defer the
     * real send() until the signature is ready — we are still between open() and
     * send(), so adding the signature headers with setRequestHeader is valid.
     *
     * Note: response DEcryption is not auto-applied at the XHR layer (the
     * response is delivered straight to the caller). It is applied for fetch
     * (installFetch); for XHR with encrypt_response, decrypt with
     * SecureBridge.processResponse() in your handler. Signing always works.
     */
    function installXHR(target) {
        var g = target || (typeof window !== 'undefined' ? window
            : (typeof globalThis !== 'undefined' ? globalThis : self));
        var XHR = g.XMLHttpRequest;
        if (!XHR || XHR.__secureBridgeXHR) { return; }
        var proto = XHR.prototype;
        var origOpen = proto.open;
        var origSend = proto.send;

        proto.open = function (method, url, async) {
            this.__sb = { method: method, url: url, async: async !== false };
            return origOpen.apply(this, arguments);
        };

        proto.send = function (body) {
            var xhr = this;
            var meta = xhr.__sb;

            // Synchronous XHR can't await async signing; non-same-origin and
            // un-tracked requests pass through untouched.
            if (!meta || meta.async === false || !isSameOrigin(meta.url)) {
                return origSend.call(xhr, body);
            }

            // Build and send the signed request. Mirrors the original behaviour:
            // on any signing failure the request still goes out unsigned.
            function doSign() {
                var client;
                try { client = instance(); } catch (e) { return origSend.call(xhr, body); }
                client.prepare(meta.method, meta.url, body === undefined ? null : body).then(function (p) {
                    // If abort() ran during the async signing gap, the request is no
                    // longer OPENED — don't send it.
                    if (xhr.readyState !== 1) { return; }
                    try {
                        var h = client.config.headers;
                        if (p.headers[h.signature]) { xhr.setRequestHeader(h.signature, p.headers[h.signature]); }
                        if (p.headers[h.timestamp]) { xhr.setRequestHeader(h.timestamp, p.headers[h.timestamp]); }
                        if (p.headers[h.nonce]) { xhr.setRequestHeader(h.nonce, p.headers[h.nonce]); }

                        var outBody = (p.body !== undefined) ? p.body : body;
                        // Only re-declare Content-Type when the body was actually
                        // transformed (e.g. encryption); for signing-only we keep the
                        // caller's body and their own Content-Type untouched.
                        if (p.headers['Content-Type'] && p.body !== undefined && p.body !== body) {
                            xhr.setRequestHeader('Content-Type', p.headers['Content-Type']);
                        }
                        origSend.call(xhr, outBody === undefined ? null : outBody);
                    } catch (e) {
                        if (xhr.readyState === 1) { origSend.call(xhr, body); }
                    }
                }, function () {
                    // Signing failed: send unsigned so the request still goes out
                    // (a protected route will reject it, surfacing the real error).
                    if (xhr.readyState === 1) { origSend.call(xhr, body); }
                });
            }

            // Legacy / manual mode — unchanged behaviour.
            if (!_auto) { return doSign(); }

            // Auto mode: fetch/refresh the per-session key first, then sign.
            // (Proactive renewal makes a 412 essentially never reach XHR callers,
            // so no mid-flight retry is attempted here.)
            ensureKey().then(function (signed) {
                if (xhr.readyState !== 1) { return; }        // aborted during handshake
                if (!signed) { return origSend.call(xhr, body); }
                doSign();
            });
        };

        // Truthy marker for idempotency + the installAxios/installJQuery guards.
        // (origSend is already captured in the closure above.)
        XHR.__secureBridgeXHR = true;
    }

    /**
     * The one call that covers everything: patches XMLHttpRequest (which also
     * covers axios, jQuery and Angular HttpClient) AND window.fetch. Call once at
     * startup (or after handshake() in token mode) and every request the app
     * already makes is signed — no other code changes.
     *
     * Note: this auto-decrypts responses only for fetch. If you enable
     * encrypt_response, decrypt XHR/axios/jQuery/Angular replies with
     * SecureBridge.processResponse(reply). Signing needs nothing extra.
     */
    function install(target) {
        var g = target || (typeof window !== 'undefined' ? window
            : (typeof globalThis !== 'undefined' ? globalThis : self));
        installXHR(target);
        // Patch fetch too, but skip a NON-native fetch (a polyfill built on
        // XMLHttpRequest) when XHR exists — the XHR patch already covers it, and
        // patching both would sign such a request twice. Any browser with Web
        // Crypto has native fetch, so this only matters in exotic setups.
        if (g && g.fetch && (isNativeFn(g.fetch) || !g.XMLHttpRequest)) {
            installFetch(target);
        }
    }

    /**
     * The single recommended setup for a SEPARATE front-end (React / Angular /
     * Vue / Svelte / plain JS) talking to a Laravel API. Call it ONCE at app
     * startup:
     *
     *   SecureBridge.start({
     *     handshake: '/secure-bridge/handshake',
     *     token: () => localStorage.getItem('auth_token'),  // function or string
     *   });
     *
     * From then on every same-origin request is signed automatically: the
     * per-session key is fetched on the first request that has a token, reused
     * until it nears expiry or the token changes, and re-fetched as needed. There
     * is nothing to wire into login, nothing to re-run after a page reload, and no
     * 412 to handle. A request made with no token is sent UNSIGNED, so public and
     * pre-login routes keep working.
     *
     * Options:
     *   handshake     {string}   the server handshake endpoint (required).
     *   token         {function|string} the current auth token; a function is
     *                            preferred so token rotation is picked up.
     *   onError       {function} called if a handshake fails (the request then
     *                            proceeds unsigned). Optional.
     *   handshakeInit {object}   extra fetch init merged into the handshake call,
     *                            e.g. { credentials: 'include' } for a cross-site
     *                            cookie setup. Optional.
     *   refreshMargin {number}   ms before the server TTL to renew the key
     *                            (default 30000). Optional.
     *   global        {object}   target global for patching (defaults to window).
     */
    function start(options) {
        options = options || {};
        _auto = {
            handshakeUrl: options.handshake || '/secure-bridge/handshake',
            tokenGetter: options.token,
            onError: options.onError,
            handshakeInit: options.handshakeInit,
            refreshMargin: options.refreshMargin
        };
        install(options.global);
    }

    /**
     * Axios request/response interceptors. NOTE: put query params in the URL
     * string (not config.params) so the signed path+query matches the wire.
     *
     * Usually unnecessary — install() already covers axios via the XHR patch.
     * Use this only if you patch axios but not XMLHttpRequest.
     */
    function installAxios(axios) {
        if (typeof XMLHttpRequest !== 'undefined' && XMLHttpRequest.__secureBridgeXHR) { return; }
        var client = instance();
        axios.interceptors.request.use(function (config) {
            var url = config.url || '';
            if (config.baseURL && !/^[a-zA-Z]+:\/\//.test(url)) {
                url = config.baseURL.replace(/\/$/, '') + (url.charAt(0) === '/' ? '' : '/') + url;
            }
            if (!isSameOrigin(url)) { return config; }
            return client.prepare(config.method || 'get', url, config.data).then(function (p) {
                config.headers = assign(config.headers || {}, p.headers);
                if (p.body !== undefined) {
                    config.data = p.body;
                    config.transformRequest = [function (d) { return d; }];
                }
                return config;
            });
        });
        axios.interceptors.response.use(function (resp) {
            if (!client.config.encryptResponse) { return resp; }
            if (resp.data && typeof resp.data === 'object') {
                return client.processResponse(resp.data).then(function (d) { resp.data = d; return resp; });
            }
            return resp;
        });
    }

    /**
     * Transparently wrap jQuery's $.ajax so EVERY existing call is signed with
     * no code changes. Because $.get / $.post / $.getJSON / $().load() all call
     * jQuery.ajax internally, they are covered too. Call once:
     *
     *   SecureBridge.configure({ key: '...' });
     *   SecureBridge.installJQuery(window.jQuery);
     *   // your existing $.ajax(...) / $.post(...) now sign automatically.
     *
     * Notes: signing is async, so the returned object is a jQuery promise
     * (.done/.fail/.then/.always work, plus a best-effort .abort()). If you rely
     * on synchronous jqXHR properties, use SecureBridge.prepare() manually.
     *
     * Usually unnecessary — install() already covers jQuery via the XHR patch.
     * Use this only if you patch jQuery but not XMLHttpRequest.
     */
    function installJQuery($) {
        if (!$ || $.__secureBridgeAjax) { return; }
        if (typeof XMLHttpRequest !== 'undefined' && XMLHttpRequest.__secureBridgeXHR) { return; }
        var origAjax = $.ajax;
        $.__secureBridgeAjax = origAjax;

        $.ajax = function (url, options) {
            // jQuery accepts $.ajax(url, options) or $.ajax(options).
            if (typeof url === 'object') { options = url; url = undefined; }
            options = options || {};
            if (url) { options.url = url; }

            var client;
            try { client = instance(); } catch (e) { return origAjax.call($, options); }

            var targetUrl = options.url || '';
            var method = (options.type || options.method || 'GET').toUpperCase();
            if (!isSameOrigin(targetUrl)) { return origAjax.call($, options); }

            // For signed GETs, fold object data into the query string BEFORE
            // signing, so the signed URL matches exactly what jQuery sends.
            if (method === 'GET' && options.data && typeof options.data === 'object') {
                var qs = $.param(options.data);
                if (qs) { targetUrl += (targetUrl.indexOf('?') === -1 ? '?' : '&') + qs; }
                options.url = targetUrl;
                delete options.data;
            }

            // Decrypt the response for the success callback too, when enabled.
            if (client.config.encryptResponse) {
                var userSuccess = options.success;
                options.success = function (data, textStatus, jqXHR) {
                    if (data && typeof data === 'object') {
                        client.processResponse(data).then(function (d) {
                            if (userSuccess) { userSuccess(d, textStatus, jqXHR); }
                        });
                    } else if (userSuccess) { userSuccess(data, textStatus, jqXHR); }
                };
            }

            var dfd = $.Deferred();
            var inner = null;

            client.prepare(method, targetUrl, options.data).then(function (p) {
                options.headers = assign(options.headers || {}, p.headers);
                options.url = p.url;
                if (p.body !== undefined) {
                    options.data = p.body;
                    options.contentType = options.contentType || 'application/json';
                    options.processData = false;
                }
                inner = origAjax.call($, options);
                inner.then(function (data, textStatus, jqXHR) {
                    if (client.config.encryptResponse && data && typeof data === 'object') {
                        client.processResponse(data).then(function (d) { dfd.resolve(d, textStatus, jqXHR); });
                    } else {
                        dfd.resolve(data, textStatus, jqXHR);
                    }
                }, function (jqXHR, textStatus, err) { dfd.reject(jqXHR, textStatus, err); });
            }, function (e) { dfd.reject(inner, 'error', e); });

            var promise = dfd.promise();
            promise.abort = function () { if (inner && inner.abort) { inner.abort(); } return promise; };
            return promise;
        };

        // Backward-compatible alias for anyone who called it explicitly.
        $.secureAjax = $.ajax;
    }

    /**
     * Fetch a per-session key from the server handshake endpoint and configure
     * the client with it (held in memory only). Call this AFTER login, passing
     * your auth token, and BEFORE installFetch().
     *
     *   await SecureBridge.handshake('/secure-bridge/handshake', {
     *     headers: { Authorization: 'Bearer ' + token }
     *   });
     */
    function handshake(url, init) {
        init = init || {};
        // Use the ORIGINAL fetch — the handshake itself is not signed (no key yet).
        var g = (typeof globalThis !== 'undefined') ? globalThis
            : (typeof window !== 'undefined' ? window : self);
        var f = g.__secureBridgeFetch || (typeof fetch !== 'undefined' ? fetch : null);
        if (!f) {
            return Promise.reject(new Error('SecureBridge: fetch is not available for handshake.'));
        }

        var subtle = getCrypto().subtle;
        var keyPair;

        // Generate a NON-EXTRACTABLE ECDSA key pair and register only the
        // public key. If the server is in HMAC mode it simply ignores the
        // public key and returns a symmetric key instead.
        return subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
            .then(function (kp) {
                keyPair = kp;
                return subtle.exportKey('spki', kp.publicKey);
            })
            .then(function (spki) {
                var headers = assign({ 'Content-Type': 'application/json' }, headersToObject(init.headers));
                var opts = assign({ credentials: 'same-origin' }, init, {
                    method: 'POST',
                    headers: headers,
                    body: JSON.stringify({ publicKey: bytesToB64(new Uint8Array(spki)) })
                });
                return f(url, opts);
            })
            .then(function (r) {
                if (!r.ok) {
                    throw new Error('SecureBridge: handshake failed with HTTP ' + r.status);
                }
                return r.json();
            })
            .then(function (cfg) {
                var client = configure(cfg);
                if (cfg.signatureDriver === 'ecdsa') {
                    client._signMode = 'ecdsa';
                    client._privateKey = keyPair.privateKey;
                }
                return client;
            });
    }

    // ---- public API ------------------------------------------------------

    var api = {
        Client: SecureBridgeClient,
        configure: configure,
        handshake: handshake,
        instance: instance,
        // proxy the common operations to the singleton for convenience
        prepare: function (m, u, b) { return instance().prepare(m, u, b); },
        signUrl: function (u) { return instance().signUrl(u); },
        encryptPayload: function (o) { return instance().encryptPayload(o); },
        decryptEnvelope: function (e) { return instance().decryptEnvelope(e); },
        processResponse: function (o) { return instance().processResponse(o); },
        start: start,
        install: install,
        installFetch: installFetch,
        installXHR: installXHR,
        installAxios: installAxios,
        installJQuery: installJQuery,
        // low-level primitives, exported for tests / advanced use
        _internal: {
            hkdf: hkdf, sha256Hex: sha256Hex, hmacHex: hmacHex,
            aesGcmEncrypt: aesGcmEncrypt, aesGcmDecrypt: aesGcmDecrypt,
            buildCanonical: buildCanonical, splitUrl: splitUrl, dropEmptyPairs: dropEmptyPairs,
            bytesToB64: bytesToB64, b64ToBytes: b64ToBytes
        },
        version: '1.6.0'
    };

    return api;
}));
