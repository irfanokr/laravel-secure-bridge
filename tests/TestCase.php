<?php

namespace Irfanokr\SecureBridge\Tests;

use Irfanokr\SecureBridge\SecureBridgeServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    /** Raw 32-byte master used across feature tests. */
    protected $master = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';

    protected function getPackageProviders($app)
    {
        return array(SecureBridgeServiceProvider::class);
    }

    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('secure-bridge.key', 'base64:' . base64_encode($this->master));
        $app['config']->set('secure-bridge.except', array());
        $app['config']->set('secure-bridge.only', array());
        $app['config']->set('cache.default', 'array');
    }
}
