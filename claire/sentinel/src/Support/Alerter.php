<?php

namespace Claire\Sentinel\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Psr\Log\LoggerInterface;
use Throwable;

class Alerter
{
    private ?LoggerInterface $logger = null;

    public function log(): LoggerInterface
    {
        return $this->logger ??= Log::build([
            'driver' => 'daily',
            'path' => storage_path('logs/sentinel.log'),
            'days' => 90,
        ]);
    }

    /**
     * Record an event and, for $alert=true, email it (throttled per $type).
     */
    public function record(string $type, string $message, array $context = [], bool $alert = false): void
    {
        $this->log()->warning("[{$type}] {$message}", $context);

        if (! $alert || ! ($to = config('sentinel.alert_email'))) {
            return;
        }

        $throttleKey = 'sentinel:mail:' . $type;
        if (! Cache::add($throttleKey, 1, now()->addMinutes((int) config('sentinel.alert_throttle_minutes', 15)))) {
            return;
        }

        $body = $message . "\n\n" . json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            . "\n\nSite: " . config('app.url') . "\nTime (UTC): " . now('UTC')->toDateTimeString()
            . "\n\nFurther alerts of this type are suppressed for " . config('sentinel.alert_throttle_minutes') . ' minutes; see storage/logs/sentinel-*.log.';

        try {
            Mail::raw($body, function ($mail) use ($to, $type) {
                $mail->to(array_map('trim', explode(',', $to)))
                    ->subject('[Sentinel] ' . parse_url((string) config('app.url'), PHP_URL_HOST) . ': ' . $type);
            });
        } catch (Throwable $e) {
            $this->log()->error('Alert mail failed: ' . $e->getMessage());
        }
    }
}
