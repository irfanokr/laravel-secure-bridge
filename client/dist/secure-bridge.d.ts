// Type definitions for secure-bridge-client 1.0.x
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

    /** Monkey-patch window.fetch to auto-sign same-origin requests/responses. */
    function installFetch(target?: any): void;
    /** Register axios request/response interceptors (put query params in the URL). */
    function installAxios(axios: any): void;
    /** Transparently wraps $.ajax (and $.get/$.post/$.getJSON) so existing calls sign automatically. No call-site changes. */
    function installJQuery($: any): void;

    const version: string;
}
