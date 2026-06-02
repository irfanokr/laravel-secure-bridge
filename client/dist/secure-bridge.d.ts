// Type definitions for secure-bridge-client 1.6.x
// Framework-agnostic client for irfanokr/laravel-secure-bridge.

export = SecureBridge;
export as namespace SecureBridge;

declare namespace SecureBridge {
    interface WireNames {
        signature: string;
        timestamp: string;
        nonce: string;
    }

    interface SecureBridgeConfig {
        /** base64 of the 32-byte master secret. May be null in ECDSA mode without encryption. */
        key: string | null;
        /** 'hmac' (default) or 'ecdsa' (non-extractable keypair via handshake()). */
        signatureDriver?: 'hmac' | 'ecdsa';
        /** Sign requests with HMAC-SHA256 + timestamp + nonce. Default: true. */
        sign?: boolean;
        /** Encrypt the request body (POST/PUT/PATCH/DELETE). Default: false. */
        encryptRequest?: boolean;
        /** Decrypt the response. Default: false. */
        encryptResponse?: boolean;
        /** 'field' (encrypt one key) or 'full' (whole body). Default: 'field'. */
        responseMode?: 'field' | 'full';
        /** Response key to decrypt in 'field' mode. Default: 'data'. */
        responseKey?: string;
        /** Recency window in seconds (informational on the client). Default: 300. */
        window?: number;
        /** Lifetime of a handshake-issued key in seconds (sent by the server). Used by start() to renew before expiry. Default: 3600. */
        expiresIn?: number;
        /** Header names. Must match the Laravel config. */
        headers?: WireNames;
        /** Query-param names for signed download links. Must match the Laravel config. */
        query?: WireNames;
    }

    interface PreparedRequest {
        url: string;
        method: string;
        headers: { [name: string]: string };
        /** Present only when the request carries a body. */
        body?: string;
    }

    class Client {
        config: Required<SecureBridgeConfig>;
        constructor(config: SecureBridgeConfig);
        /** Encrypt (if enabled) and sign a request. */
        prepare(method: string, url: string, body?: any): Promise<PreparedRequest>;
        /** Append signature query params to a GET URL (downloads / window.open). */
        signUrl(url: string): Promise<string>;
        /** Encrypt an arbitrary value into a v1 envelope. */
        encryptPayload(value: any): Promise<string>;
        /** Decrypt a v1 envelope back into a value. */
        decryptEnvelope(envelope: string): Promise<any>;
        /** Decrypt the data field (or whole body) of a parsed JSON response. */
        processResponse(responseJson: any): Promise<any>;
    }

    /** Configure the singleton client used by the convenience/install functions. */
    function configure(config: SecureBridgeConfig): Client;
    /**
     * Fetch a per-session key from the server handshake endpoint (after login)
     * and configure the client with it. Held in memory only.
     */
    function handshake(url: string, init?: RequestInit | { headers?: any; [k: string]: any }): Promise<Client>;
    /** The configured singleton (throws if configure() was not called). */
    function instance(): Client;

    function prepare(method: string, url: string, body?: any): Promise<PreparedRequest>;
    function signUrl(url: string): Promise<string>;
    function encryptPayload(value: any): Promise<string>;
    function decryptEnvelope(envelope: string): Promise<any>;
    function processResponse(responseJson: any): Promise<any>;

    interface StartOptions {
        /** Server handshake endpoint, e.g. '/secure-bridge/handshake'. */
        handshake: string;
        /** The current auth token, read on every request. A function is preferred so token rotation is picked up. */
        token?: (() => string | null | undefined) | string;
        /** Called if a handshake fails; the request then proceeds unsigned. */
        onError?: (err: unknown) => void;
        /** Extra fetch init merged into the handshake call (e.g. { credentials: 'include' }). */
        handshakeInit?: RequestInit | { headers?: any;[k: string]: any };
        /** Milliseconds before the server TTL to renew the key. Default: 30000. */
        refreshMargin?: number;
        /** Target global for patching (defaults to window). */
        global?: any;
    }

    /**
     * Recommended single-call setup for a separate front-end. Register ONCE at app
     * startup; every same-origin request is then signed automatically. The key is
     * fetched lazily on the first request that has a token, reused until it nears
     * expiry or the token changes, and re-fetched as needed — no login wiring, no
     * reload wiring, no 412 handling. A request with no token is sent unsigned.
     */
    function start(options: StartOptions): void;
    /** The one call that covers everything: patches window.fetch AND XMLHttpRequest (so fetch, raw XHR, axios, jQuery and Angular HttpClient are all signed). No call-site changes. */
    function install(target?: any): void;
    /** Monkey-patch window.fetch to auto-sign same-origin requests/responses. */
    function installFetch(target?: any): void;
    /** Patch XMLHttpRequest so every XHR (incl. axios, jQuery, Angular HttpClient) is signed. No call-site changes. */
    function installXHR(target?: any): void;
    /** Register axios request/response interceptors. Usually unnecessary — install() already covers axios via the XHR patch. */
    function installAxios(axios: any): void;
    /** Wrap $.ajax so existing calls sign automatically. Usually unnecessary — install() already covers jQuery via the XHR patch. */
    function installJQuery($: any): void;

    const version: string;
}
