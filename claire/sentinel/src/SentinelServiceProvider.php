<?php

namespace Claire\Sentinel;

use Claire\Sentinel\Console\BaselineCommand;
use Claire\Sentinel\Console\ScanCommand;
use Claire\Sentinel\Console\UnbanCommand;
use Claire\Sentinel\Http\Middleware\Firewall;
use Claire\Sentinel\Listeners\AdminActivityMonitor;
use Claire\Sentinel\Scanner\IntegrityScanner;
use Claire\Sentinel\Support\Alerter;
use Claire\Sentinel\Support\IpBanner;
use Claire\Sentinel\Support\UploadInspector;
use Illuminate\Auth\Events\Login;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class SentinelServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sentinel.php', 'sentinel');

        $this->app->singleton(Alerter::class);
        $this->app->singleton(IpBanner::class);
        $this->app->singleton(UploadInspector::class);
        $this->app->bind(IntegrityScanner::class, fn () => new IntegrityScanner(base_path()));
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../config/sentinel.php' => config_path('sentinel.php')], 'sentinel-config');

        if ($this->app->runningInConsole()) {
            $this->commands([BaselineCommand::class, ScanCommand::class, UnbanCommand::class]);
        }

        if (! config('sentinel.enabled', true)) {
            return;
        }

        // Global, so it also covers requests that match no route (probes) and every upload.
        $this->app->make(HttpKernel::class)->pushMiddleware(Firewall::class);

        Event::listen(Login::class, [AdminActivityMonitor::class, 'onLogin']);

        $userModel = config('sentinel.admin.user_model');
        if ($userModel && class_exists($userModel)) {
            $userModel::saved(fn ($user) => $this->app->make(AdminActivityMonitor::class)->onSaved($user));
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            $when = trim((string) config('sentinel.integrity.schedule', 'hourly'));
            if ($when === '') {
                return;
            }
            $event = $schedule->command('sentinel:scan --fix')->withoutOverlapping(60);
            match ($when) {
                'hourly' => $event->hourly(),
                'daily' => $event->daily(),
                default => $event->cron($when),
            };
        });
    }
}
