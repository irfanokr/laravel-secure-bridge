<?php

namespace Irfanokr\SecureBridge\Console;

use Illuminate\Console\Command;

class KeygenCommand extends Command
{
    protected $signature = 'secure-bridge:keygen
                            {--show : Print the key instead of writing it to the .env file}
                            {--force : Overwrite an existing key without confirmation}';

    protected $description = 'Generate a SecureBridge master key and set SECURE_BRIDGE_KEY in your .env file';

    public function handle()
    {
        $key = 'base64:' . base64_encode(random_bytes(32));

        if ($this->option('show')) {
            $this->line($key);

            return 0;
        }

        if (! $this->setKeyInEnvironmentFile($key)) {
            return 1;
        }

        // Refresh the in-memory config so subsequent commands in this process see it.
        $this->laravel['config']['secure-bridge.key'] = $key;

        $this->info('SecureBridge master key set successfully.');
        $this->line('Use the SAME key (base64 part) when configuring your JavaScript client.');

        return 0;
    }

    protected function setKeyInEnvironmentFile($key)
    {
        $path = $this->envPath();

        if (! file_exists($path)) {
            $this->error('.env file not found at ' . $path . '.');
            $this->line('Run with --show to print a key and add SECURE_BRIDGE_KEY manually.');

            return false;
        }

        $contents = file_get_contents($path);
        $current = $this->currentKeyValue($contents);

        if ($current !== null && $current !== '' && ! $this->option('force')) {
            $this->warn('SECURE_BRIDGE_KEY is already set.');
            $this->line('Rotating it will break already-issued signed/encrypted traffic unless you');
            $this->line('move the old value into SECURE_BRIDGE_PREVIOUS_KEYS first.');
            if (! $this->confirm('Overwrite the existing key?')) {
                return false;
            }
        }

        if (preg_match('/^SECURE_BRIDGE_KEY=.*$/m', $contents)) {
            $contents = preg_replace('/^SECURE_BRIDGE_KEY=.*$/m', 'SECURE_BRIDGE_KEY=' . $key, $contents);
        } else {
            $contents = rtrim($contents, "\r\n") . "\n" . 'SECURE_BRIDGE_KEY=' . $key . "\n";
        }

        file_put_contents($path, $contents);

        return true;
    }

    protected function currentKeyValue($contents)
    {
        if (preg_match('/^SECURE_BRIDGE_KEY=(.*)$/m', $contents, $m)) {
            return trim($m[1]);
        }

        return null;
    }

    protected function envPath()
    {
        if (method_exists($this->laravel, 'environmentFilePath')) {
            return $this->laravel->environmentFilePath();
        }

        return $this->laravel->basePath('.env');
    }
}
