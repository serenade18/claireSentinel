<?php

namespace ClaireSentinel\Scanner;

use ClaireSentinel\Support\Signatures;
use ClaireSentinel\Support\UploadInspector;
use FilesystemIterator;
use RecursiveCallbackFilterIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

class IntegrityScanner
{
    public const CRITICAL = 'critical';
    public const WARNING = 'warning';

    private string $root;

    public function __construct(?string $root = null)
    {
        $this->root = rtrim($root ?? base_path(), '/');
    }

    /* ------------------------------------------------------------------ */
    /* Baseline                                                             */
    /* ------------------------------------------------------------------ */

    public function buildBaseline(): array
    {
        $files = [];
        foreach ($this->watchedFiles() as $rel => $abs) {
            $files[$rel] = hash_file('sha256', $abs);
        }
        ksort($files);

        return ['created_at' => now()->toIso8601String(), 'files' => $files];
    }

    public function writeBaseline(array $baseline): string
    {
        $path = config('sentinel.integrity.baseline_path');
        if (! is_dir(dirname($path))) {
            mkdir(dirname($path), 0750, true);
        }
        $baseline['hmac'] = $this->sign($baseline['files']);
        file_put_contents($path, json_encode($baseline, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
        @chmod($path, 0640);

        return $path;
    }

    /** @return array{0: ?array, 1: ?string} [baseline, error] */
    public function readBaseline(): array
    {
        $path = config('sentinel.integrity.baseline_path');
        if (! is_file($path)) {
            return [null, 'missing'];
        }
        $data = json_decode((string) file_get_contents($path), true);
        if (! is_array($data) || ! isset($data['files'], $data['hmac'])) {
            return [null, 'unreadable'];
        }
        if (! hash_equals($this->sign($data['files']), (string) $data['hmac'])) {
            return [null, 'signature mismatch (baseline was edited outside sentinel:baseline, or APP_KEY changed)'];
        }
        return [$data, null];
    }

    private function sign(array $files): string
    {
        return hash_hmac('sha256', json_encode($files, JSON_UNESCAPED_SLASHES), (string) config('app.key'));
    }

    /* ------------------------------------------------------------------ */
    /* Scan                                                                 */
    /* ------------------------------------------------------------------ */

    /**
     * @return array<int, array{severity: string, type: string, path: string, detail: string, quarantinable: bool}>
     */
    public function scan(): array
    {
        $findings = [];

        // 1. Integrity against the baseline
        [$baseline, $error] = $this->readBaseline();
        if ($error) {
            $findings[] = $this->finding($error === 'missing' ? self::WARNING : self::CRITICAL, 'baseline', config('sentinel.integrity.baseline_path'), "Baseline {$error}. Run: php artisan sentinel:baseline");
        } else {
            $current = $this->buildBaseline()['files'];
            foreach ($current as $rel => $hash) {
                if (! isset($baseline['files'][$rel])) {
                    $findings[] = $this->finding(self::CRITICAL, 'added', $rel, 'File added since baseline', $this->autoQuarantinable($rel));
                } elseif (! hash_equals($baseline['files'][$rel], $hash)) {
                    $findings[] = $this->finding(self::CRITICAL, 'modified', $rel, 'File changed since baseline');
                }
            }
            foreach (array_diff_key($baseline['files'], $current) as $rel => $_) {
                $findings[] = $this->finding(self::WARNING, 'removed', $rel, 'File removed since baseline');
            }
        }

        // 2. Whole-tree sweep: stray scripts, signatures, binaries, rogue .htaccess, hidden dirs
        $publicAllowed = (array) config('sentinel.integrity.public_scripts_allowed', []);
        $htaccessAllowed = array_merge((array) config('sentinel.integrity.htaccess_allowed', []), array_keys((array) config('sentinel.integrity.guards', [])));
        $hiddenAllowed = (array) config('sentinel.integrity.hidden_dirs_allowed', []);
        $self = $this->packagePath();
        $maxBytes = (int) config('sentinel.integrity.max_file_bytes', 5242880);

        foreach ((array) config('sentinel.integrity.scan', ['.']) as $scanRoot) {
            foreach ($this->iterate($scanRoot, (array) config('sentinel.integrity.scan_exclude', []), true) as $rel => $info) {
                if ($info->isDir()) {
                    $name = $info->getFilename();
                    if ($name[0] === '.' && ! in_array($name, $hiddenAllowed, true) && ! $this->under($rel, ['vendor', 'node_modules'])) {
                        $findings[] = $this->finding(self::CRITICAL, 'hidden-dir', $rel, 'Unexpected hidden directory');
                    }
                    continue;
                }

                $name = $info->getFilename();
                $size = $info->getSize();

                if ($name === '.htaccess') {
                    $content = (string) @file_get_contents($info->getPathname());
                    if ($hit = Signatures::match($content, Signatures::htaccess())) {
                        $findings[] = $this->finding(self::CRITICAL, 'htaccess', $rel, "Malicious .htaccess ({$hit})", true);
                    } elseif (! in_array($rel, $htaccessAllowed, true)) {
                        $findings[] = $this->finding(self::CRITICAL, 'htaccess', $rel, 'Unexpected .htaccess', true);
                    }
                    continue;
                }

                if (in_array($name, ['.user.ini', 'php.ini'], true) && ! $this->under($rel, ['vendor'])) {
                    $findings[] = $this->finding(self::CRITICAL, 'php-ini', $rel, 'PHP ini override (can auto_prepend a backdoor)', true);
                    continue;
                }

                if ($size >= 4 && ! $this->under($rel, ['node_modules'])) {
                    $head = (string) @file_get_contents($info->getPathname(), false, null, 0, 4);
                    if ($head === "\x7fELF") {
                        $findings[] = $this->finding(self::CRITICAL, 'binary', $rel, 'Native executable (e.g. crypto miner)', true);
                        continue;
                    }
                }

                if (preg_match('#\.zip$#i', $name) && $this->under($rel, (array) config('sentinel.integrity.inspect_archives_in', []))
                    && ($reason = app(UploadInspector::class)->inspectZip($info->getPathname()))) {
                    $findings[] = $this->finding(self::CRITICAL, 'archive', $rel, "Dangerous archive: {$reason}", true);
                    continue;
                }

                if (! Signatures::isScriptName($name)) {
                    continue;
                }

                if (str_starts_with($rel, 'public/') && ! in_array($rel, $publicAllowed, true)) {
                    $findings[] = $this->finding(self::CRITICAL, 'public-script', $rel, 'Script file under public/', true);
                    continue;
                }

                // This package's signature list and test fixtures contain malware strings by design
                // (they are still hashed into the baseline, so any tampering or new file is reported).
                if ($size > $maxBytes || ($self !== null && ($rel === "{$self}/src/Support/Signatures.php" || str_starts_with($rel, "{$self}/tests/")))) {
                    continue;
                }
                $content = (string) @file_get_contents($info->getPathname());
                if ($hit = Signatures::match($content, Signatures::php(strongOnly: $this->under($rel, ['vendor'])))) {
                    $findings[] = $this->finding(self::CRITICAL, 'signature', $rel, "Malware signature: {$hit}", true);
                }
            }
        }

        // 3. Guard files (upload no-exec rules) must be present and intact
        foreach ($this->guardStatus() as $rel => $ok) {
            if (! $ok) {
                $findings[] = $this->finding(self::CRITICAL, 'guard', $rel, 'Protective file missing or altered');
            }
        }

        // Decide what --fix may move. Files the baseline knows (e.g. a backdoored
        // public/index.php) are never moved: the site would break, so a human restores them.
        $protected = array_merge($publicAllowed, $htaccessAllowed);
        foreach ($findings as &$f) {
            if (! $f['quarantinable']) {
                continue;
            }
            $known = $baseline ? isset($baseline['files'][$f['path']]) : null;
            if (in_array($f['path'], $protected, true) || $known === true) {
                $f['quarantinable'] = false;
            } elseif ($known === null) {
                // No trusted baseline: only move clear-cut attacker files or anything in the risky folders.
                $f['quarantinable'] = in_array($f['type'], ['binary', 'archive', 'htaccess', 'public-script'], true) || $this->autoQuarantinable($f['path']);
            } elseif ($f['type'] === 'added') {
                // New file without other evidence: only in the risky folders.
                $f['quarantinable'] = $this->autoQuarantinable($f['path']);
            }
        }
        unset($f);

        // One finding per path (keep the first/most specific)
        $unique = [];
        foreach ($findings as $f) {
            $unique[$f['type'] === 'baseline' ? 'baseline' : $f['path'] . '|' . $f['type']] = $f;
        }
        return array_values($unique);
    }

    /* ------------------------------------------------------------------ */
    /* Remediation                                                          */
    /* ------------------------------------------------------------------ */

    /** @return array<string, bool> guard path => intact (only guards whose folder exists) */
    public function guardStatus(): array
    {
        $status = [];
        foreach ((array) config('sentinel.integrity.guards', []) as $rel => $stub) {
            $abs = $this->root . '/' . $rel;
            if (! is_dir(dirname($abs))) {
                continue;
            }
            $status[$rel] = is_file($abs) && hash_file('sha256', $abs) === hash_file('sha256', $this->stub($stub));
        }
        return $status;
    }

    /** @return string[] restored guard paths */
    public function restoreGuards(): array
    {
        $restored = [];
        $guards = (array) config('sentinel.integrity.guards', []);
        foreach ($this->guardStatus() as $rel => $ok) {
            if ($ok) {
                continue;
            }
            $abs = $this->root . '/' . $rel;
            if (is_file($abs)) {
                @chmod($abs, 0644);
            }
            copy($this->stub($guards[$rel]), $abs);
            @chmod($abs, 0444);
            $restored[] = $rel;
        }
        return $restored;
    }

    /** Move a file into quarantine (keeping its relative path). Returns the new location. */
    public function quarantine(string $rel, string $stamp): ?string
    {
        $abs = $this->root . '/' . $rel;
        if (! is_file($abs)) {
            return null;
        }
        $dest = rtrim(config('sentinel.integrity.quarantine_path'), '/') . "/{$stamp}/{$rel}";
        if (! is_dir(dirname($dest))) {
            mkdir(dirname($dest), 0750, true);
        }
        @chmod($abs, 0644);
        if (! @rename($abs, $dest)) {
            return null;
        }
        @chmod($dest, 0400);
        file_put_contents(dirname($dest, substr_count($rel, '/') + 1) . '/manifest.txt', hash_file('sha256', $dest) . "  {$rel}\n", FILE_APPEND | LOCK_EX);

        return $dest;
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                              */
    /* ------------------------------------------------------------------ */

    /** @return iterable<string, string> relative => absolute */
    private function watchedFiles(): iterable
    {
        $exclude = (array) config('sentinel.integrity.watch_exclude', []);
        foreach ((array) config('sentinel.integrity.watch', []) as $entry) {
            $abs = $this->root . '/' . $entry;
            if (is_file($abs)) {
                yield $entry => $abs;
            } elseif (is_dir($abs)) {
                foreach ($this->iterate($entry, $exclude, false) as $rel => $info) {
                    if ($info->isFile()) {
                        yield $rel => $info->getPathname();
                    }
                }
            }
        }
    }

    /** @return iterable<string, SplFileInfo> */
    private function iterate(string $start, array $exclude, bool $withDirs): iterable
    {
        $abs = $start === '.' ? $this->root : $this->root . '/' . trim($start, '/');
        if (! is_dir($abs)) {
            return;
        }

        $filter = function (SplFileInfo $current) use ($exclude) {
            if ($current->isLink()) {
                return false;
            }
            $rel = $this->relative($current->getPathname());
            foreach ($exclude as $pattern) {
                if (preg_match($pattern, $rel)) {
                    return false;
                }
            }
            return true;
        };

        $it = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(new RecursiveDirectoryIterator($abs, FilesystemIterator::SKIP_DOTS), $filter),
            $withDirs ? RecursiveIteratorIterator::SELF_FIRST : RecursiveIteratorIterator::LEAVES_ONLY,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        foreach ($it as $info) {
            yield $this->relative($info->getPathname()) => $info;
        }
    }

    private function relative(string $abs): string
    {
        return ltrim(substr($abs, strlen($this->root)), '/');
    }

    private function under(string $rel, array $prefixes): bool
    {
        foreach ($prefixes as $p) {
            $p = trim($p, '/');
            if ($p === '' || $rel === $p || str_starts_with($rel, $p . '/')) {
                return true;
            }
        }
        return false;
    }

    private function autoQuarantinable(string $rel): bool
    {
        return $this->under($rel, (array) config('sentinel.integrity.auto_quarantine', []));
    }

    private function stub(string $name): string
    {
        return dirname(__DIR__, 2) . '/resources/stubs/' . $name;
    }

    /** This package's folder relative to the scanned root, or null when installed elsewhere. */
    private function packagePath(): ?string
    {
        $dir = realpath(dirname(__DIR__, 2));
        $root = realpath($this->root);
        if ($dir === false || $root === false || ! str_starts_with($dir, $root . DIRECTORY_SEPARATOR)) {
            return null;
        }

        return str_replace(DIRECTORY_SEPARATOR, '/', substr($dir, strlen($root) + 1));
    }

    private function finding(string $severity, string $type, string $path, string $detail, bool $quarantinable = false): array
    {
        return compact('severity', 'type', 'path', 'detail', 'quarantinable');
    }
}
