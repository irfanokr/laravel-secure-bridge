<?php

namespace Irfanokr\SecureBridge;

use Illuminate\Support\Facades\Blade;
use Illuminate\Support\ServiceProvider;
use Irfanokr\SecureBridge\Console\DoctorCommand;
use Irfanokr\SecureBridge\Console\KeygenCommand;
use Irfanokr\SecureBridge\Http\HandshakeController;
use Irfanokr\SecureBridge\Http\Middleware\CspMiddleware;
use Irfanokr\SecureBridge\Http\Middleware\SecureBridgeMiddleware;

class SecureBridgeServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/secure-bridge.php', 'secure-bridge');

        $this->app->singleton('secure-bridge', function ($app) {
            return new SecureBridge($app, $app['config']->get('secure-bridge', array()));
        });

        $this->app->alias('secure-bridge', SecureBridge::class);
    }

    public function boot()
    {
        // Publishable config.
        $this->publishes(array(
            __DIR__ . '/../config/secure-bridge.php' => $this->configPath(),
        ), 'secure-bridge-config');

        // Blade directive view.
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'secure-bridge');
        $this->publishes(array(
            __DIR__ . '/../resources/views' => $this->resourcePath('views/vendor/secure-bridge'),
        ), 'secure-bridge-views');

        // Pre-built JavaScript client (UMD) for same-origin Blade apps.
        $this->publishes(array(
            __DIR__ . '/../client/dist' => $this->publicPath('vendor/secure-bridge'),
        ), 'secure-bridge-assets');

        // "secure-bridge" middleware alias.
        $router = $this->app['router'];
        if (method_exists($router, 'aliasMiddleware')) {
            $router->aliasMiddleware('secure-bridge', SecureBridgeMiddleware::class);
            $router->aliasMiddleware('secure-bridge.csp', CspMiddleware::class);
        } else {
            // Laravel < 5.4
            $router->middleware('secure-bridge', SecureBridgeMiddleware::class);
            $router->middleware('secure-bridge.csp', CspMiddleware::class);
        }

        if ($this->app->runningInConsole()) {
            $this->commands(array(KeygenCommand::class, DoctorCommand::class));
        }

        $this->registerHandshakeRoute($router);
        $this->registerBladeDirective();
    }

    protected function registerHandshakeRoute($router)
    {
        $config = $this->app['config'];
        if (! $config->get('secure-bridge.handshake.enabled')) {
            return;
        }

        $route = $config->get('secure-bridge.handshake.route', 'secure-bridge/handshake');
        $middleware = $config->get('secure-bridge.handshake.middleware', array('auth'));

        $router->post($route, HandshakeController::class)->middleware($middleware);
    }

    protected function registerBladeDirective()
    {
        // @secureBridge — injects the client script + per-session/static config.
        Blade::directive('secureBridge', function () {
            return "<?php echo view('secure-bridge::client', ['sbConfig' => app('secure-bridge')->clientConfig()])->render(); ?>";
        });

        // @cspNonce — the per-request CSP nonce, for <script nonce="@cspNonce">.
        Blade::directive('cspNonce', function () {
            return "<?php echo e(app('secure-bridge')->cspNonce()); ?>";
        });
    }

    protected function configPath()
    {
        return function_exists('config_path')
            ? config_path('secure-bridge.php')
            : $this->app->basePath('config/secure-bridge.php');
    }

    protected function resourcePath($path)
    {
        return function_exists('resource_path')
            ? resource_path($path)
            : $this->app->basePath('resources/' . $path);
    }

    protected function publicPath($path)
    {
        return function_exists('public_path')
            ? public_path($path)
            : $this->app->basePath('public/' . $path);
    }
}
