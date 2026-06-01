{{-- SecureBridge client bootstrap. Emitted by the @secureBridge directive. --}}
@if(!empty($sbConfig['key']))
<script src="{{ asset('vendor/secure-bridge/secure-bridge.umd.js') }}"></script>
<script>
    (function () {
        if (!window.SecureBridge || typeof window.SecureBridge.configure !== 'function') {
            console.error('SecureBridge client script failed to load. Did you run: php artisan vendor:publish --tag=secure-bridge-assets ?');
            return;
        }
        window.SecureBridge.configure(@json($sbConfig));
        // Auto-wire same-origin AJAX (window.fetch + jQuery if present).
        if (typeof window.SecureBridge.installFetch === 'function') {
            window.SecureBridge.installFetch();
        }
        if (window.jQuery && typeof window.SecureBridge.installJQuery === 'function') {
            window.SecureBridge.installJQuery(window.jQuery);
        }
    })();
</script>
@else
<!-- SecureBridge: no key configured. Run `php artisan secure-bridge:keygen`. -->
@endif
