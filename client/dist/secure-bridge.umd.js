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
        // Multipart/binary bodies are never encrypted.
        var needEnc = hasBody && cfg.encryptRequest && !isForm && !isUrlEnc;
        var needSym = needEnc || (cfg.sign && !isEcdsa);

        var keysPromise = needSym ? self._derive() : Promise.resolve(null);

        return keysPromise.then(function (keys) {
            var headers = {};
            var sendBody;            // what we actually transmit
            var hashStringPromise;   // string to hash for the canonical ('' = body-less)

            if (!hasBody) {
                sendBody = undefined;
                hashStringPromise = Promise.resolve('');
            } else if (isForm) {
                // The browser sets the multipart boundary + Content-Type; we
                // sign body-less (the server matches with an empty body digest).
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

            var client = instance();
            return client.prepare(method, url, init.body).then(function (p) {
                var merged = assign(headersToObject(init.headers), p.headers);
                var newInit = assign({}, init, { method: p.method, headers: merged });
                if (p.body !== undefined) { newInit.body = p.body; }
                return orig(p.url, newInit);
            }).then(function (resp) {
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
            });
        };
    }

    /**
     * Axios request/response interceptors. NOTE: put query params in the URL
     * string (not config.params) so the signed path+query matches the wire.
     */
    function installAxios(axios) {
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
     * jQuery helper. Usage:
     *   $.secureAjax({ url: '/api/x', type: 'POST', data: {...} }).then(function (data) { ... });
     * Resolves with the (decrypted) response payload.
     */
    function installJQuery($) {
        $.secureAjax = function (options) {
            options = options || {};
            var client = instance();
            return client.prepare(options.type || options.method || 'GET', options.url || '', options.data).then(function (p) {
                options.headers = assign(options.headers || {}, p.headers);
                if (p.body !== undefined) {
                    options.data = p.body;
                    options.contentType = 'application/json';
                    options.processData = false;
                }
                return $.ajax(options);
            }).then(function (data) {
                if (client.config.encryptResponse && data && typeof data === 'object') {
                    return client.processResponse(data);
                }
                return data;
            });
        };
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
        installFetch: installFetch,
        installAxios: installAxios,
        installJQuery: installJQuery,
        // low-level primitives, exported for tests / advanced use
        _internal: {
            hkdf: hkdf, sha256Hex: sha256Hex, hmacHex: hmacHex,
            aesGcmEncrypt: aesGcmEncrypt, aesGcmDecrypt: aesGcmDecrypt,
            buildCanonical: buildCanonical, splitUrl: splitUrl, dropEmptyPairs: dropEmptyPairs,
            bytesToB64: bytesToB64, b64ToBytes: b64ToBytes
        },
        version: '1.2.0'
    };

    return api;
}));
