<?php

namespace Claire\Sentinel\Tests;

use App\Models\User;
use Claire\Sentinel\Listeners\AdminActivityMonitor;
use Claire\Sentinel\Support\Alerter;
use Illuminate\Auth\Events\Login;
use Tests\TestCase;

class AdminMonitorTest extends TestCase
{
    private array $records = [];

    protected function setUp(): void
    {
        parent::setUp();
        $records = &$this->records;
        $this->app->instance(Alerter::class, new class ($records) extends Alerter {
            public function __construct(private array &$sink)
            {
            }

            public function record(string $type, string $message, array $context = [], bool $alert = false): void
            {
                $this->sink[] = compact('type', 'message', 'context', 'alert');
            }
        });
    }

    private function user(string $role, array $attrs = []): User
    {
        $user = new User();
        $user->forceFill(['id' => 7, 'email' => "{$role}@example.test", 'user_type' => $role] + $attrs);
        $user->syncOriginal();
        return $user;
    }

    public function test_admin_login_alerts(): void
    {
        event(new Login('web', $this->user('admin'), false));
        $this->assertCount(1, $this->records);
        $this->assertSame('admin-login', $this->records[0]['type']);
        $this->assertTrue($this->records[0]['alert']);
    }

    public function test_customer_login_is_silent(): void
    {
        event(new Login('web', $this->user('customer'), false));
        $this->assertSame([], $this->records);
    }

    public function test_new_admin_account_alerts(): void
    {
        $user = $this->user('admin');
        $user->wasRecentlyCreated = true;
        app(AdminActivityMonitor::class)->onSaved($user);
        $this->assertStringContainsString('New privileged account', $this->records[0]['message']);
    }

    public function test_promotion_to_admin_alerts(): void
    {
        $user = $this->user('customer');
        $user->user_type = 'admin';
        $user->syncChanges();
        app(AdminActivityMonitor::class)->onSaved($user);
        $this->assertStringContainsString('promoted to admin', $this->records[0]['message']);
    }

    public function test_admin_password_change_alerts_but_customer_does_not(): void
    {
        $admin = $this->user('admin', ['password' => 'old']);
        $admin->password = 'new';
        $admin->syncChanges();
        app(AdminActivityMonitor::class)->onSaved($admin);

        $customer = $this->user('customer', ['password' => 'old']);
        $customer->password = 'new';
        $customer->syncChanges();
        app(AdminActivityMonitor::class)->onSaved($customer);

        $this->assertCount(1, $this->records);
        $this->assertStringContainsString('password changed', $this->records[0]['message']);
    }
}
