<?php
/**
 * PHP side of the cross-language conformance harness.
 *
 *   php interop_php.php emit              -> prints a JSON fixture
 *   php interop_php.php decrypt <envelope> -> prints the decrypted plaintext
 *
 * Run by tests/interop/run.ps1 to prove the Laravel package and the JS client
 * produce byte-identical signatures and mutually-decryptable ciphertext.
 */

$base = __DIR__ . '/../../src/';
require $base . 'Support/Hkdf.php';
require $base . 'Support/Canonicalizer.php';
require $base . 'Contracts/SignatureDriver.php';
require $base . 'Contracts/EncryptionDriver.php';
require $base . 'Exceptions/SecureBridgeException.php';
require $base . 'Exceptions/DecryptionException.php';
require $base . 'Drivers/Signature/HmacSignatureDriver.php';
require $base . 'Drivers/Encryption/AesGcmEncryptionDriver.php';

use Irfanokr\SecureBridge\Drivers\Encryption\AesGcmEncryptionDriver;
use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\Hkdf;

$master = '0123456789abcdef0123456789abcdef'; // 32 raw bytes, fixed for determinism
$masterB64 = base64_encode($master);
$signKey = Hkdf::derive($master, 32, 'secure-bridge:sign:v1');
$encKey  = Hkdf::derive($master, 32, 'secure-bridge:enc:v1');

$mode = isset($argv[1]) ? $argv[1] : 'emit';

if ($mode === 'emit') {
    $method = 'POST';
    $path   = '/api/login';
    $query  = 'lang=en&x=1';
    $ts     = '1700000000';
    $nonce  = 'abc123nonce';
    $body   = '{"username":"demo","pin":4321}';

    $canonical = Canonicalizer::build($method, $path, $query, $ts, $nonce, hash('sha256', $body));
    $sig = 'v1=' . (new HmacSignatureDriver())->sign($canonical, $signKey);
    $env = (new AesGcmEncryptionDriver())->encrypt($body, $encKey);

    echo json_encode(array(
        'master'       => $masterB64,
        'method'       => $method,
        'path'         => $path,
        'query'        => $query,
        'ts'           => $ts,
        'nonce'        => $nonce,
        'body'         => $body,
        'canonical'    => $canonical,
        'sig'          => $sig,
        'php_envelope' => $env,
    ));
} elseif ($mode === 'decrypt') {
    $env = isset($argv[2]) ? $argv[2] : '';
    echo (new AesGcmEncryptionDriver())->decrypt(trim($env), $encKey);
} else {
    fwrite(STDERR, "unknown mode\n");
    exit(2);
}
