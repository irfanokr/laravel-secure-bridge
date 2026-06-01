<?php

namespace Irfanokr\SecureBridge\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array config($key = null, $default = null)
 * @method static \Irfanokr\SecureBridge\Contracts\SignatureDriver signatureDriver()
 * @method static \Irfanokr\SecureBridge\Contracts\EncryptionDriver encryptionDriver()
 * @method static \Irfanokr\SecureBridge\Support\KeyChain staticKeyChain()
 * @method static \Irfanokr\SecureBridge\Support\KeyChain keyChainForRequest($request = null)
 * @method static bool verifyCanonical($canonical, $signatureValue, \Irfanokr\SecureBridge\Support\KeyChain $keyChain)
 * @method static string signCanonical($canonical, \Irfanokr\SecureBridge\Support\KeyChain $keyChain)
 * @method static string encryptString($plaintext, \Irfanokr\SecureBridge\Support\KeyChain $keyChain)
 * @method static string decryptString($envelope, \Irfanokr\SecureBridge\Support\KeyChain $keyChain)
 * @method static array clientConfig($request = null)
 *
 * @see \Irfanokr\SecureBridge\SecureBridge
 */
class SecureBridge extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'secure-bridge';
    }
}
