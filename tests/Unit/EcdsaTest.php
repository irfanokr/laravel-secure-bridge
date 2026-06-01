<?php

namespace Irfanokr\SecureBridge\Tests\Unit;

use Irfanokr\SecureBridge\Drivers\Signature\EcdsaSignatureDriver;
use PHPUnit\Framework\TestCase;

/**
 * Frozen vector captured from the Web Crypto client (tests/interop/ecdsa_client_node.js):
 * a NON-EXTRACTABLE ECDSA P-256 keypair signed this canonical message; PHP must
 * verify it via openssl. Locks the P1363->DER + SPKI->PEM conversion.
 */
class EcdsaTest extends TestCase
{
    private $publicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7X3JdnvbdFHhfgBB8XFOjKJ/BuUT3YL7Mz0HQrO84Cg0kceKeKpNhEBzBP8yHCDO6N1SuTRlgxzEQvSaHzPpzg==';

    private $signature = 'Cv9M3bNjRbclTZ2Qhk2kFvTolWl1VHi8XDIMowhqiyAY27hbDMcYUsNYOA89xCadOMUaymWY1AWxoo5OTebOMw==';

    private $message = "POST\n/api/login\nlang=en\n1780307597\n4f3cdabf3689befecd2b479ddbc05d3e\n81929628c47858155fb802bdd2aa243760778e0c48e32d1165a3232b361664d3";

    public function testVerifiesWebCryptoEcdsaSignature()
    {
        $driver = new EcdsaSignatureDriver();
        $this->assertTrue($driver->verify($this->message, $this->signature, $this->publicKey));
    }

    public function testRejectsTamperedMessage()
    {
        $driver = new EcdsaSignatureDriver();
        $this->assertFalse($driver->verify($this->message . 'x', $this->signature, $this->publicKey));
    }

    public function testRejectsCorruptedSignature()
    {
        $driver = new EcdsaSignatureDriver();
        $corrupt = strtr($this->signature, 'AB', 'BA');
        $this->assertFalse($driver->verify($this->message, $corrupt, $this->publicKey));
    }

    public function testRejectsGarbageInputsWithoutError()
    {
        $driver = new EcdsaSignatureDriver();
        $this->assertFalse($driver->verify($this->message, 'not-base64-!!!', $this->publicKey));
        $this->assertFalse($driver->verify($this->message, $this->signature, 'not-a-key'));
    }
}
