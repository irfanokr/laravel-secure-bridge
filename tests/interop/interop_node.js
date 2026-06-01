/**
 * JS side of the cross-language conformance harness.
 *
 *   node interop_node.js <fixture.json> <out_envelope.txt>
 *
 * Verifies the client reproduces the PHP canonical string + signature exactly,
 * decrypts the PHP-produced AES-GCM envelope, and emits a fresh envelope for
 * PHP to decrypt in turn. Exits non-zero if any check fails.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const SecureBridge = require(path.join(__dirname, '..', '..', 'client', 'dist', 'secure-bridge.umd.js'));

(async function () {
    const fixturePath = process.argv[2];
    const outPath = process.argv[3];
    const fx = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

    const client = SecureBridge.configure({
        key: fx.master,
        sign: true,
        encryptRequest: true,
        encryptResponse: true
    });

    const keys = await client._derive();
    const I = SecureBridge._internal;

    const bodyHash = await I.sha256Hex(fx.body);
    const canonical = I.buildCanonical(fx.method, fx.path, fx.query, fx.ts, fx.nonce, bodyHash);
    const nodeSig = 'v1=' + await I.hmacHex(keys.sign, canonical);

    const canonMatch = canonical === fx.canonical;
    const sigMatch = nodeSig === fx.sig;

    const decrypted = await I.aesGcmDecrypt(keys.enc, fx.php_envelope);
    const decMatch = decrypted === fx.body;

    // Produce an envelope for PHP to decrypt.
    const nodeEnv = await I.aesGcmEncrypt(keys.enc, fx.body);
    fs.writeFileSync(outPath, nodeEnv);

    const report = {
        canonical_match: canonMatch,
        signature_match: sigMatch,
        php_envelope_decrypted_by_node: decMatch,
        node_signature: nodeSig,
        php_signature: fx.sig,
        decrypted_plaintext: decrypted
    };
    console.log(JSON.stringify(report, null, 2));

    if (!(canonMatch && sigMatch && decMatch)) {
        console.error('INTEROP FAIL (node side)');
        process.exit(1);
    }
})().catch(function (e) {
    console.error(e && e.stack ? e.stack : e);
    process.exit(1);
});
