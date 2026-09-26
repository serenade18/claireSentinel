<?php

namespace ClaireSentinel\Tests;

use ClaireSentinel\Tests\Fixtures\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Route;
use ZipArchive;

class FirewallTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Minimal route with no DB-backed middleware, so only the global firewall is exercised.
        Route::any('/_sentinel/probe-test', fn () => 'ok');
        Route::post('/admin/addons', fn () => 'installed');
    }

    private function ip(string $ip): static
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $ip]);
    }

    public function test_clean_request_passes(): void
    {
        $this->ip('10.0.0.1')->get('/_sentinel/probe-test')->assertOk()->assertSee('ok');
    }

    public function test_backdoor_paths_are_blocked_and_ban_immediately(): void
    {
        // Defaults plus an app-specific backdoor added in config.
        config(['sentinel.firewall.honeypot_paths' => array_merge(config('sentinel.firewall.honeypot_paths'), ['#^import-data$#i'])]);
        foreach (['/wso.php', '/uploads/c99.php', '/import-data', '/wp-cron.zip'] as $i => $path) {
            $ip = "10.0.1.{$i}";
            $this->ip($ip)->get($path)->assertForbidden();
            $this->ip($ip)->get('/_sentinel/probe-test')->assertForbidden(); // now banned
        }
    }

    public function test_probe_paths_are_blocked(): void
    {
        foreach (['/.env', '/wp-login.php', '/uploads/all/22.php', '/uploads/product/cyb01.php', '/uploads/all/x.php.jpg', '/vendor/phpunit/x', '/shop.sql', '/.git/config', '/cgi-bin/src/index.php'] as $i => $path) {
            $this->ip("10.0.2.{$i}")->get($path)->assertForbidden();
        }
    }

    public function test_path_rules_spare_the_front_controller_and_real_routes(): void
    {
        $matches = function (string $path): bool {
            foreach (config('sentinel.firewall.blocked_paths') as $pattern) {
                if (preg_match($pattern, $path)) {
                    return true;
                }
            }
            return false;
        };
        foreach (['index.php', 'admin/config/settings', 'shop/app-store', 'app/dashboard', 'config/profile', 'storage/avatars/a.png', 'api/v2/products', 'changelog'] as $ok) {
            $this->assertFalse($matches($ok), "{$ok} should not be blocked");
        }
        foreach (['uploads/index.php', 'x.php.jpg', 'shell.phtml', 'a/b/c.php7', '.env.backup', 'vendor/autoload.php'] as $bad) {
            $this->assertTrue($matches($bad), "{$bad} should be blocked");
        }
    }

    public function test_repeated_probes_trigger_ban_and_unban_lifts_it(): void
    {
        config(['sentinel.firewall.max_strikes' => 3]);
        $ip = '10.0.4.1';
        $this->ip($ip)->get('/.env')->assertForbidden();
        $this->ip($ip)->get('/_sentinel/probe-test')->assertOk();
        $this->ip($ip)->get('/.git/config')->assertForbidden();
        $this->ip($ip)->get('/wp-login.php')->assertForbidden();
        $this->ip($ip)->get('/_sentinel/probe-test')->assertForbidden(); // 3 strikes: banned

        $this->artisan('sentinel:unban', ['ip' => $ip])->assertSuccessful();
        $this->ip($ip)->get('/_sentinel/probe-test')->assertOk();
    }

    public function test_cdn_edge_ip_is_blocked_but_never_banned(): void
    {
        $cf = '172.68.10.10'; // Cloudflare edge
        $this->ip($cf)->get('/wso.php')->assertForbidden();
        $this->ip($cf)->post('/_sentinel/probe-test')->assertOk();
    }

    public function test_allowlisted_ip_is_never_blocked(): void
    {
        config(['sentinel.firewall.allow_ips' => ['10.0.5.1']]);
        $this->ip('10.0.5.1')->get('/_sentinel/probe-test?f=zip://evil')->assertOk();
    }

    public function test_malicious_input_is_blocked(): void
    {
        $this->ip('10.0.6.1')->get('/_sentinel/probe-test?page=zip://public/wp-cron.zip%23x')->assertForbidden();
        $this->ip('10.0.6.2')->get('/_sentinel/probe-test?file=../../.env')->assertForbidden();
        $this->ip('10.0.6.3')->post('/_sentinel/probe-test', ['description' => '<?php system($_GET["c"]); ?>'])->assertForbidden();
        $this->ip('10.0.6.4')->post('/_sentinel/probe-test', ['a' => ['b' => 'phar://x.phar']])->assertForbidden();
    }

    public function test_rich_text_with_relative_paths_is_allowed(): void
    {
        $this->ip('10.0.7.1')->post('/_sentinel/probe-test', ['description' => '<p><img src="../uploads/all/a.png"> 5 < 6 ?></p>'])->assertOk();
    }

    public function test_upload_with_php_payload_in_image_is_blocked(): void
    {
        $png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
        $file = UploadedFile::fake()->createWithContent('logo.png', $png . '<?php eval($_POST[1]); ?>');
        $this->ip('10.0.8.1')->post('/_sentinel/probe-test', ['aiz_file' => $file])->assertForbidden();
    }

    public function test_upload_with_dangerous_names_is_blocked(): void
    {
        foreach (['shell.php', 'shell.php.jpg', 'x.phtml', '22.php56', '.htaccess', '.user.ini', 'a.PhAr'] as $i => $name) {
            $file = UploadedFile::fake()->createWithContent($name, 'hello');
            $this->ip("10.0.9.{$i}")->post('/_sentinel/probe-test', ['aiz_file' => $file])->assertForbidden();
        }
    }

    public function test_clean_uploads_pass(): void
    {
        $png = base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==');
        $this->ip('10.0.10.1')->post('/_sentinel/probe-test', ['aiz_file' => UploadedFile::fake()->createWithContent('photo.png', $png)])->assertOk();
        $this->ip('10.0.10.2')->post('/_sentinel/probe-test', ['aiz_file' => UploadedFile::fake()->createWithContent('prices.csv', "sku,price\nA1,10\n")])->assertOk();
        $this->ip('10.0.10.3')->post('/_sentinel/probe-test', ['aiz_file' => $this->zip('photos.zip', ['a.png' => $png, 'dir/b.png' => $png])])->assertOk();
        $this->ip('10.0.10.4')->post('/_sentinel/probe-test', ['aiz_file' => $this->zip('sheet.xlsx', ['[Content_Types].xml' => '<?xml version="1.0"?><Types/>', 'xl/workbook.xml' => '<?xml version="1.0"?><workbook/>'])])->assertOk();
    }

    public function test_malicious_archives_are_blocked(): void
    {
        $cases = [
            'zip slip' => ['../scheduler-run.php' => '<?php system($_REQUEST["c"]);'],
            'deep slip' => ['a/../../../env-read.php' => 'x'],
            'script inside' => ['addon/logo.php' => '<?php eval(base64_decode("x"));'],
            'extensionless php' => ['wp-cron' => '<?php echo 1;'],
            'htaccess inside' => ['.htaccess' => 'Allow from all'],
        ];
        $i = 0;
        foreach ($cases as $label => $entries) {
            $this->ip('10.0.11.' . $i++)->post('/_sentinel/probe-test', ['uploaded_file' => $this->zip('x.zip', $entries)])
                ->assertForbidden();
        }
    }

    public function test_code_archive_needs_flag_path_and_privileged_user(): void
    {
        $plugin = fn () => $this->zip('plugin.zip', ['plugin/src/Plugin.php' => '<?php class Plugin {}']);
        $admin = new User(['id' => 1, 'email' => 'a@example.test', 'role' => 'admin']);
        $customer = new User(['id' => 2, 'email' => 'c@example.test', 'role' => 'customer']);

        // Off by default, even for an admin on the installer path.
        $this->actingAs($admin)->ip('10.0.12.1')->post('/admin/addons', ['file' => $plugin()])->assertForbidden();

        config(['sentinel.uploads.allow_code_archives' => true, 'sentinel.uploads.code_archive_paths' => ['#^admin/addons$#']]);

        $this->actingAs($admin)->ip('10.0.12.2')->post('/admin/addons', ['file' => $plugin()])->assertOk()->assertSee('installed');
        $this->actingAs($customer)->ip('10.0.12.3')->post('/admin/addons', ['file' => $plugin()])->assertForbidden();
        // Only on the configured path.
        $this->actingAs($admin)->ip('10.0.12.4')->post('/_sentinel/probe-test', ['file' => $plugin()])->assertForbidden();
        // Path traversal is never allowed, even for an admin.
        $this->actingAs($admin)->ip('10.0.12.5')->post('/admin/addons', ['file' => $this->zip('p.zip', ['../x.php' => '<?php'])])->assertForbidden();
    }

    public function test_code_archive_from_guest_is_blocked(): void
    {
        config(['sentinel.uploads.allow_code_archives' => true, 'sentinel.uploads.code_archive_paths' => ['#^admin/addons$#']]);
        $this->ip('10.0.13.1')->post('/admin/addons', ['file' => $this->zip('plugin.zip', ['a.php' => '<?php echo 1;'])])->assertForbidden();
    }

    public function test_firewall_can_be_used_as_route_middleware_only(): void
    {
        $this->assertArrayHasKey('sentinel.firewall', app('router')->getMiddleware());
    }

    private function zip(string $name, array $entries): UploadedFile
    {
        $path = tempnam(sys_get_temp_dir(), 'snt');
        $zip = new ZipArchive();
        $zip->open($path, ZipArchive::OVERWRITE);
        foreach ($entries as $entry => $content) {
            $zip->addFromString($entry, $content);
        }
        $zip->close();

        return new UploadedFile($path, $name, null, null, true);
    }
}
