<?php

namespace ClaireSentinel;

use ClaireSentinel\Console\BaselineCommand;
use ClaireSentinel\Console\ScanCommand;
use ClaireSentinel\Console\UnbanCommand;
use ClaireSentinel\Http\Middleware\Firewall;
use ClaireSentinel\Http\Middleware\RequirePrivilegedUploader;
use ClaireSentinel\Listeners\AdminActivityMonitor;
use ClaireSentinel\Scanner\IntegrityScanner;
use ClaireSentinel\Support\Alerter;
use ClaireSentinel\Support\IpBanner;
use ClaireSentinel\Support\Privileges;
use ClaireSentinel\Support\UploadInspector;
use Illuminate\Auth\Events\Login;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class SentinelServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sentinel.php', 'sentinel');

        $this->app->singleton(Alerter::class);
        $this->app->singleton(IpBanner::class);
        $this->app->singleton(Privileges::class);
        $this->app->singleton(UploadInspector::class);
        $this->app->bind(IntegrityScanner::class, fn () => new IntegrityScanner(base_path()));
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../config/sentinel.php' => config_path('sentinel.php')], 'sentinel-config');

        if ($this->app->runningInConsole()) {
            $this->commands([BaselineCommand::class, ScanCommand::class, UnbanCommand::class]);
        }

        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('sentinel.firewall', Firewall::class);

        if (! config('sentinel.enabled', true)) {
            return;
        }

        if (config('sentinel.firewall.global', true)) {
            // Global, so it also covers requests that match no route (probes) and every upload.
            $kernel = $this->app->make(HttpKernel::class);
            if (method_exists($kernel, 'pushMiddleware')) {
                $kernel->pushMiddleware(Firewall::class);
            }
        }

        // Archives with code that the firewall deferred are checked once the route's
        // session and auth middleware have run (appended last, so it runs after them).
        Event::listen(RouteMatched::class, function (RouteMatched $event) {
            if ($event->request->attributes->has(Firewall::CODE_ARCHIVES)) {
                $event->route->middleware(RequirePrivilegedUploader::class);
                // Recompute even if the list was cached (long-lived workers reuse route objects).
                $event->route->computedMiddleware = null;
            }
        });

        if (config('sentinel.admin.enabled', true)) {
            Event::listen(Login::class, [AdminActivityMonitor::class, 'onLogin']);

            $userModel = config('sentinel.admin.user_model') ?: config('auth.providers.users.model');
            if (is_string($userModel) && class_exists($userModel) && is_subclass_of($userModel, Model::class)) {
                $userModel::created(fn ($user) => $this->app->make(AdminActivityMonitor::class)->onCreated($user));
                $userModel::updated(fn ($user) => $this->app->make(AdminActivityMonitor::class)->onUpdated($user));
            }
        }

        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            $when = trim((string) config('sentinel.integrity.schedule', 'hourly'));
            if ($when === '') {
                return;
            }
            $command = filter_var(config('sentinel.integrity.schedule_fix', true), FILTER_VALIDATE_BOOLEAN) ? 'sentinel:scan --fix' : 'sentinel:scan';
            $event = $schedule->command($command)->withoutOverlapping(60);
            match ($when) {
                'hourly' => $event->hourly(),
                'daily' => $event->daily(),
                default => $event->cron($when),
            };
        });
    }
}
