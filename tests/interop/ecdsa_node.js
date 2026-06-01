// Generate an ECDSA P-256 keypair in Web Crypto, sign a message, and emit the
// SPKI public key + P1363 signature for PHP (EcdsaSignatureDriver) to verify.
'use strict';
const fs = require('fs');

function b64(bytes) { return Buffer.from(bytes).toString('base64'); }

(async function () {
    const subtle = globalThis.crypto.subtle;
    const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const spki = new Uint8Array(await subtle.exportKey('spki', kp.publicKey));

    const message = 'POST\n/api/login\nlang=en\n1700000000\nnonce-1\n' +
        Buffer.from(await subtle.digest('SHA-256', new TextEncoder().encode('{"u":"demo"}'))).toString('hex');

    const sig = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey,
        new TextEncoder().encode(message)));

    const out = { publicKey: b64(spki), signature: b64(sig), message: message };
    fs.writeFileSync(process.argv[2], JSON.stringify(out));
    console.log('ECDSA fixture written (P1363 sig ' + sig.length + ' bytes, SPKI ' + spki.length + ' bytes)');
})().catch(function (e) { console.error(e); process.exit(1); });
