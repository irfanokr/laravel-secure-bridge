// Full client-path ECDSA test: generate a NON-EXTRACTABLE keypair, drive the
// real client's prepare() to produce a signature, and emit a fixture for PHP
// (EcdsaSignatureDriver) to verify — proving the end-to-end asymmetric flow.
'use strict';
const fs = require('fs');
const path = require('path');
const SecureBridge = require(path.join(__dirname, '..', '..', 'client', 'dist', 'secure-bridge.umd.js'));

function b64(bytes) { return Buffer.from(bytes).toString('base64'); }

(async function () {
    const subtle = globalThis.crypto.subtle;

    // Non-extractable private key; public key still exportable (per spec).
    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const spki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));
    console.log('non-extractable keypair OK; public SPKI exported (' + spki.length + ' bytes)');

    const client = new SecureBridge.Client({ key: null, signatureDriver: 'ecdsa', sign: true });
    client._signMode = 'ecdsa';
    client._privateKey = kp.privateKey;

    const url = 'http://localhost/api/login?lang=en';
    const prepared = await client.prepare('POST', url, { u: 'demo' });

    // Reconstruct exactly what the client signed.
    const I = SecureBridge._internal;
    const ts = prepared.headers['X-Timestamp'];
    const nonce = prepared.headers['X-Nonce'];
    const bodyHash = await I.sha256Hex(prepared.body);
    const canonical = I.buildCanonical('POST', '/api/login', 'lang=en', ts, nonce, bodyHash);

    const sigHeader = prepared.headers['X-Sig'];          // "v1=<base64>"
    const signature = sigHeader.slice(sigHeader.indexOf('=') + 1);

    const out = { publicKey: b64(spki), signature: signature, message: canonical };
    fs.writeFileSync(process.argv[2], JSON.stringify(out));
    console.log('client produced ECDSA signature; fixture written for PHP verify');
})().catch(function (e) { console.error(e && e.stack ? e.stack : e); process.exit(1); });
