<?php

namespace ClaireSentinel\Console;

use ClaireSentinel\Scanner\IntegrityScanner;
use ClaireSentinel\Support\Alerter;
use Illuminate\Console\Command;

class ScanCommand extends Command
{
    protected $signature = 'sentinel:scan
        {--fix : Restore guard files and move quarantinable findings to storage/app/sentinel/quarantine}
        {--json : Output findings as JSON}';

    protected $description = 'Check code integrity and sweep the project for webshells, stray scripts, miners and rogue .htaccess files.';

    public function handle(IntegrityScanner $scanner, Alerter $alerter): int
    {
        $findings = $scanner->scan();
        $actions = [];

        if ($this->option('fix')) {
            foreach ($scanner->restoreGuards() as $rel) {
                $actions[] = "restored {$rel}";
            }
            $stamp = now()->format('Ymd-His');
            foreach ($findings as &$f) {
                if ($f['quarantinable'] && ($dest = $scanner->quarantine($f['path'], $stamp))) {
                    $f['detail'] .= ' [QUARANTINED]';
                    $actions[] = "quarantined {$f['path']}";
                }
            }
            unset($f);
        }

        if ($this->option('json')) {
            $this->line(json_encode(['findings' => $findings, 'actions' => $actions], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } elseif ($findings) {
            $this->table(['Severity', 'Type', 'Path', 'Detail'], array_map(fn ($f) => [$f['severity'], $f['type'], $f['path'], $f['detail']], $findings));
            foreach ($actions as $a) {
                $this->line("  - {$a}");
            }
        } else {
            $this->info('Sentinel: no findings.');
        }

        $critical = array_values(array_filter($findings, fn ($f) => $f['severity'] === IntegrityScanner::CRITICAL));
        if ($critical) {
            $alerter->record('integrity', count($critical) . ' critical finding(s) from sentinel:scan', [
                'findings' => array_map(fn ($f) => "{$f['type']}: {$f['path']} ({$f['detail']})", array_slice($critical, 0, 50)),
                'actions' => $actions,
                'next_steps' => 'Investigate each file. After a legitimate deploy run: php artisan sentinel:baseline',
            ], alert: true);
        }

        return $critical ? self::FAILURE : self::SUCCESS;
    }
}
