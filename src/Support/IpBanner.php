<?php

namespace ClaireSentinel\Support;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\IpUtils;

class IpBanner
{
    public function isAllowed(?string $ip): bool
    {
        return $ip !== null && in_array($ip, (array) config('sentinel.firewall.allow_ips', []), true);
    }

    public function isBanned(?string $ip): bool
    {
        return $ip !== null && $this->cache()->has($this->banKey($ip));
    }

    public function isBannable(string $ip): bool
    {
        return ! IpUtils::checkIp($ip, (array) config('sentinel.firewall.never_ban_ranges', []));
    }

    public function ban(string $ip, ?int $minutes = null): void
    {
        if (! $this->isBannable($ip)) {
            return;
        }
        $minutes ??= (int) config('sentinel.firewall.ban_minutes', 1440);
        $this->cache()->put($this->banKey($ip), now()->toIso8601String(), now()->addMinutes($minutes));
    }

    public function unban(string $ip): void
    {
        $this->cache()->forget($this->banKey($ip));
        $this->cache()->forget($this->strikeKey($ip));
    }

    /**
     * Add strikes; returns true when the IP has just been banned.
     */
    public function strike(string $ip, int $weight = 1): bool
    {
        $key = $this->strikeKey($ip);
        $window = now()->addMinutes((int) config('sentinel.firewall.strike_window_minutes', 10));

        $this->cache()->add($key, 0, $window);
        $strikes = (int) $this->cache()->increment($key, $weight);

        if ($strikes >= (int) config('sentinel.firewall.max_strikes', 5) && $this->isBannable($ip)) {
            $this->ban($ip);
            return true;
        }
        return false;
    }

    public function cache(): Repository
    {
        return Cache::store(config('sentinel.firewall.cache_store') ?: null);
    }

    private function banKey(string $ip): string
    {
        return 'sentinel:ban:' . sha1($ip);
    }

    private function strikeKey(string $ip): string
    {
        return 'sentinel:strikes:' . sha1($ip);
    }
}
