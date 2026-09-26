<?php

namespace ClaireSentinel\Http\Middleware;

use ClaireSentinel\Support\Alerter;
use ClaireSentinel\Support\Privileges;
use Closure;
use Illuminate\Http\Request;

/**
 * Second half of the code-archive check. The firewall runs before the session
 * starts, so it defers archives that contain code; this middleware is appended
 * to the matched route (after its session and auth middleware) and only lets
 * them through for a privileged user.
 */
class RequirePrivilegedUploader
{
    public function __construct(private Firewall $firewall, private Privileges $privileges, private Alerter $alerter)
    {
    }

    public function handle(Request $request, Closure $next)
    {
        $archives = (array) $request->attributes->get(Firewall::CODE_ARCHIVES, []);
        if (! $archives) {
            return $next($request);
        }

        $user = $request->user();
        if (! $this->privileges->isPrivileged($user)) {
            return $this->firewall->block($request, 'upload', 'Code archive upload by a non-privileged user: ' . implode(', ', $archives), weight: 3, alert: true);
        }

        $this->alerter->record('code-upload', 'Privileged user uploaded an archive containing code: ' . implode(', ', $archives), [
            'user_id' => $user->getAuthIdentifier(),
            'ip' => $request->ip(),
            'url' => $request->fullUrl(),
        ], alert: true);

        return $next($request);
    }
}
