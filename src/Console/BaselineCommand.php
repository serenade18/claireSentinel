<?php

namespace ClaireSentinel\Console;

use ClaireSentinel\Scanner\IntegrityScanner;
use ClaireSentinel\Support\Alerter;
use Illuminate\Console\Command;

class BaselineCommand extends Command
{
    protected $signature = 'sentinel:baseline {--force : Overwrite without confirmation}';

    protected $description = 'Record SHA-256 hashes of the application code as the trusted baseline (run after every legitimate deploy).';

    public function handle(IntegrityScanner $scanner, Alerter $alerter): int
    {
        [$existing] = $scanner->readBaseline();
        if ($existing && ! $this->option('force') && ! $this->confirm('A baseline exists. Replace it with the current state of the code?', true)) {
            return self::FAILURE;
        }

        $this->info('Hashing watched files...');
        $baseline = $scanner->buildBaseline();
        $path = $scanner->writeBaseline($baseline);

        $alerter->record('baseline', 'Integrity baseline recorded', ['files' => count($baseline['files']), 'console' => true]);
        $this->info(sprintf('Baseline of %d files written to %s', count($baseline['files']), $path));
        $this->line('Only run this on code you trust: anything present now is treated as clean.');

        return self::SUCCESS;
    }
}
