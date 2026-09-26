<?php

namespace ClaireSentinel\Tests;

use ClaireSentinel\Listeners\AdminActivityMonitor;
use ClaireSentinel\Support\Alerter;
use ClaireSentinel\Tests\Fixtures\OnlyIdSevenIsAdmin;
use ClaireSentinel\Tests\Fixtures\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

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

    private function user(array $attrs): User
    {
        $user = new User();
        $user->forceFill(['id' => 7, 'email' => 'user@example.test'] + $attrs);
        $user->syncOriginal();

        return $user;
    }

    public function test_admin_login_alerts(): void
    {
        event(new Login('web', $this->user(['role' => 'admin']), false));
        $this->assertCount(1, $this->records);
        $this->assertSame('admin-login', $this->records[0]['type']);
        $this->assertSame('admin', $this->records[0]['context']['role']);
        $this->assertTrue($this->records[0]['alert']);
    }

    public function test_customer_login_is_silent(): void
    {
        event(new Login('web', $this->user(['role' => 'customer']), false));
        $this->assertSame([], $this->records);
    }

    public function test_boolean_admin_flag_is_recognised(): void
    {
        config(['sentinel.admin.role_attribute' => null]);
        event(new Login('web', $this->user(['is_admin' => true]), false));
        event(new Login('web', $this->user(['is_admin' => false]), false));
        $this->assertCount(1, $this->records);
    }

    public function test_custom_resolver_decides(): void
    {
        config(['sentinel.admin.resolver' => OnlyIdSevenIsAdmin::class]);
        event(new Login('web', $this->user(['role' => 'customer']), false));
        $this->assertSame('owner', $this->records[0]['context']['role']);
    }

    public function test_new_admin_account_alerts(): void
    {
        $user = $this->user(['role' => 'admin']);
        app(AdminActivityMonitor::class)->onCreated($user);
        $this->assertStringContainsString('New privileged account', $this->records[0]['message']);
    }

    public function test_promotion_to_admin_alerts(): void
    {
        $user = $this->user(['role' => 'customer']);
        $user->role = 'admin';
        $user->syncChanges();
        app(AdminActivityMonitor::class)->onUpdated($user);
        $this->assertStringContainsString('promoted to admin', $this->records[0]['message']);
    }

    public function test_admin_password_change_alerts_but_customer_does_not(): void
    {
        $admin = $this->user(['role' => 'admin', 'password' => 'old']);
        $admin->password = 'new';
        $admin->syncChanges();
        app(AdminActivityMonitor::class)->onUpdated($admin);

        $customer = $this->user(['role' => 'customer', 'password' => 'old']);
        $customer->password = 'new';
        $customer->syncChanges();
        app(AdminActivityMonitor::class)->onUpdated($customer);

        $this->assertCount(1, $this->records);
        $this->assertStringContainsString('password changed', $this->records[0]['message']);
    }

    public function test_other_admin_changes_are_silent_without_privilege_attributes(): void
    {
        config(['sentinel.admin.role_attribute' => null, 'sentinel.admin.flag_attributes' => [], 'sentinel.admin.resolver' => OnlyIdSevenIsAdmin::class]);
        $admin = $this->user(['name' => 'Old']);
        $admin->name = 'New';
        $admin->syncChanges();
        app(AdminActivityMonitor::class)->onUpdated($admin);
        $this->assertSame([], $this->records);
    }

    public function test_model_hook_fires_on_real_saves(): void
    {
        Schema::create('users', function (Blueprint $t) {
            $t->id();
            $t->string('email');
            $t->string('password')->nullable();
            $t->string('role')->default('customer');
            $t->boolean('is_admin')->default(false);
            $t->timestamps();
        });

        $user = User::create(['email' => 'c@example.test', 'role' => 'customer']);
        $this->assertSame([], $this->records);

        $user->update(['role' => 'admin']);
        $this->assertStringContainsString('promoted to admin', $this->records[0]['message']);

        User::create(['email' => 'root@example.test', 'is_admin' => true]);
        $this->assertStringContainsString('New privileged account', $this->records[1]['message']);
    }
}
