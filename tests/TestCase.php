<?php

namespace ClaireSentinel\Tests;

use ClaireSentinel\SentinelServiceProvider;
use ClaireSentinel\Tests\Fixtures\User;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [SentinelServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', 'base64:' . base64_encode(str_repeat('k', 32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('mail.default', 'array');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('sentinel.alert_email', null);
        $app['config']->set('sentinel.firewall.allow_ips', []);
        $app['config']->set('sentinel.admin.role_attribute', 'role');
    }
}
