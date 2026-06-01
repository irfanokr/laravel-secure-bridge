<?php
// Clean re-check of the frozen signature vector (no shell escaping involved).
$b = __DIR__ . '/../../src/';
require $b . 'Support/Hkdf.php';
require $b . 'Support/Canonicalizer.php';
require $b . 'Contracts/SignatureDriver.php';
require $b . 'Drivers/Signature/HmacSignatureDriver.php';

use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\Hkdf;

$master = '0123456789abcdef0123456789abcdef';
$sign = Hkdf::derive($master, 32, 'secure-bridge:sign:v1');
$body = '{"username":"demo","pin":4321}';
$canonical = Canonicalizer::build('POST', '/api/login', 'lang=en&x=1', '1700000000', 'abc123nonce', hash('sha256', $body));
$sig = (new HmacSignatureDriver())->sign($canonical, $sign);

$expected = '1b7af77f9c9139aef55bb37ef0fe63af729293ccd8bfd0c6ce5fcf1c2bf2ea21';
echo 'bodyHash = ' . hash('sha256', $body) . "\n";
echo 'sig      = ' . $sig . "\n";
echo 'expected = ' . $expected . "\n";
echo ($sig === $expected ? "FROZEN VECTOR OK\n" : "FROZEN VECTOR MISMATCH\n");
exit($sig === $expected ? 0 : 1);
