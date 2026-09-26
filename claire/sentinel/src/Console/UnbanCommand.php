<?php

namespace Claire\Sentinel\Console;

use Claire\Sentinel\Support\IpBanner;
use Illuminate\Console\Command;

class UnbanCommand extends Command
{
    protected $signature = 'sentinel:unban {ip : The IP address to unban}';

    protected $description = 'Lift a Sentinel firewall ban and reset strikes for an IP.';

    public function handle(IpBanner $banner): int
    {
        $ip = (string) $this->argument('ip');
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error('Not a valid IP address.');
            return self::FAILURE;
        }
        $banner->unban($ip);
        $this->info("Unbanned {$ip}.");

        return self::SUCCESS;
    }
}
