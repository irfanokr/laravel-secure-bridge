<?php

namespace Irfanokr\SecureBridge\Tests\Unit;

use Irfanokr\SecureBridge\Drivers\Encryption\AesGcmEncryptionDriver;
use Irfanokr\SecureBridge\Drivers\Signature\HmacSignatureDriver;
use Irfanokr\SecureBridge\Exceptions\DecryptionException;
use Irfanokr\SecureBridge\Support\Canonicalizer;
use Irfanokr\SecureBridge\Support\Hkdf;
use Irfanokr\SecureBridge\Support\KeyChain;
use PHPUnit\Framework\TestCase;

/**
 * Pure crypto unit tests — no Laravel required. The "frozen vector" test below
 * is the contract with the JavaScript client: if it ever changes, the wire
 * format changed and every client breaks. It must match tests/interop output.
 */
class CryptoTest extends TestCase
{
    private $master = '0123456789abcdef0123456789abcdef'; // 32 raw bytes

    public function testHkdfIsDeterministicAndDomainSeparated()
    {
        $sign = Hkdf::derive($this->master, 32, 'secure-bridge:sign:v1');
        $enc  = Hkdf::derive($this->master, 32, 'secure-bridge:enc:v1');

        $this->assertSame(32, strlen($sign));
        $this->assertSame(32, strlen($enc));
        $this->assertNotSame($sign, $enc, 'sign and enc subkeys must differ');
        // Deterministic
        $this->assertSame(bin2hex($sign), bin2hex(Hkdf::derive($this->master, 32, 'secure-bridge:sign:v1')));
    }

    public function testFrozenSignatureVector()
    {
        // This vector is reproduced byte-for-byte by secure-bridge-client.
        $signKey = Hkdf::derive($this->master, 32, 'secure-bridge:sign:v1');

        $canonical = Canonicalizer::build(
            'POST',
            '/api/login',
            'lang=en&x=1',
            '1700000000',
            'abc123nonce',
            hash('sha256', '{"username":"demo","pin":4321}')
        );

        $sig = (new HmacSignatureDriver())->sign($canonical, $signKey);

        $this->assertSame(
            '1b7af77f9c9139aef55bb37ef0fe63af729293ccd8bfd0c6ce5fcf1c2bf2ea21',
            $sig,
            'Wire-format signature vector changed — every client will break.'
        );
    }

    public function testHmacVerifyIsConstantTimeAndCaseInsensitiveHex()
    {
        $driver = new HmacSignatureDriver();
        $key = random_bytes(32);
        $sig = $driver->sign('hello', $key);

        $this->assertTrue($driver->verify('hello', $sig, $key));
        $this->assertTrue($driver->verify('hello', strtoupper($sig), $key));
        $this->assertFalse($driver->verify('hello', $sig, random_bytes(32)));
        $this->assertFalse($driver->verify('tampered', $sig, $key));
    }

    public function testAesGcmRoundTrip()
    {
        $driver = new AesGcmEncryptionDriver();
        $key = Hkdf::derive($this->master, 32, 'secure-bridge:enc:v1');

        $plaintext = '{"secret":"value","n":42}';
        $envelope = $driver->encrypt($plaintext, $key);

        $this->assertStringStartsWith('v1.', $envelope);
        $this->assertSame($plaintext, $driver->decrypt($envelope, $key));
    }

    public function testAesGcmRejectsTamperedCiphertext()
    {
        $driver = new AesGcmEncryptionDriver();
        $key = Hkdf::derive($this->master, 32, 'secure-bridge:enc:v1');

        $envelope = $driver->encrypt('hello world', $key);
        // Flip a character in the ciphertext segment.
        $parts = explode('.', $envelope);
        $parts[2] = strrev($parts[2]);
        $tampered = implode('.', $parts);

        $this->expectException(DecryptionException::class);
        $driver->decrypt($tampered, $key);
    }

    public function testKeyChainDecodesBase64AndRaw()
    {
        $raw = KeyChain::decode('base64:' . base64_encode($this->master));
        $this->assertSame($this->master, $raw);

        $this->assertSame('plainsecret', KeyChain::decode('plainsecret'));
        $this->assertNull(KeyChain::decode(''));
        $this->assertNull(KeyChain::decode(null));
    }

    public function testCanonicalQueryStripsEmptyAndSignatureParams()
    {
        $q = Canonicalizer::canonicalQuery('a=1&&b=2&__sb_sig=x&__sb_ts=1&__sb_nonce=n', array('__sb_sig', '__sb_ts', '__sb_nonce'));
        $this->assertSame('a=1&b=2', $q);
    }
}
