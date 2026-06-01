<?php
// Verify the Web Crypto ECDSA signature produced by ecdsa_node.js.
$base = __DIR__ . '/../../src/';
require $base . 'Contracts/SignatureDriver.php';
require $base . 'Exceptions/SecureBridgeException.php';
require $base . 'Drivers/Signature/EcdsaSignatureDriver.php';

use Irfanokr\SecureBridge\Drivers\Signature\EcdsaSignatureDriver;

$fixture = json_decode(file_get_contents($argv[1]), true);

$driver = new EcdsaSignatureDriver();
$ok = $driver->verify($fixture['message'], $fixture['signature'], $fixture['publicKey']);
echo $ok ? "ECDSA VERIFY OK\n" : "ECDSA VERIFY FAILED\n";

// Negative control: a tampered message must fail.
$bad = $driver->verify($fixture['message'] . 'x', $fixture['signature'], $fixture['publicKey']);
echo (! $bad) ? "TAMPER REJECTED OK\n" : "TAMPER NOT REJECTED (BAD)\n";

exit(($ok && ! $bad) ? 0 : 1);
