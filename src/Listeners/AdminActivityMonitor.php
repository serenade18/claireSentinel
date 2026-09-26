<?php

namespace ClaireSentinel\Listeners;

use ClaireSentinel\Support\Alerter;
use ClaireSentinel\Support\Privileges;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\Eloquent\Model;

/**
 * Alerts on privileged logins and on accounts gaining admin rights,
 * the two things an attacker needs to install plugins or edit settings.
 */
class AdminActivityMonitor
{
    public function __construct(private Alerter $alerter, private Privileges $privileges)
    {
    }

    public function onLogin(Login $event): void
    {
        if (! config('sentinel.admin.alert_on_login', true) || ! $this->privileges->isPrivileged($event->user)) {
            return;
        }

        $request = app()->runningInConsole() ? null : request();
        $this->alerter->record('admin-login', 'Privileged login: ' . ($event->user->email ?? ('#' . $event->user->getAuthIdentifier())), [
            'user_id' => $event->user->getAuthIdentifier(),
            'role' => $this->privileges->role($event->user),
            'guard' => $event->guard,
            'ip' => $request?->ip(),
            'user_agent' => $request?->userAgent(),
            'url' => $request?->fullUrl(),
        ], alert: true);
    }

    public function onCreated(Model $user): void
    {
        $this->check($user, created: true);
    }

    public function onUpdated(Model $user): void
    {
        $this->check($user, created: false);
    }

    // Separate hooks: wasRecentlyCreated stays true on an instance after later updates.
    private function check(Model $user, bool $created): void
    {
        if (! $this->privileges->isPrivileged($user)) {
            return;
        }

        // wasChanged([]) means "anything changed", so only ask when there are attributes to watch.
        $attributes = $this->privileges->privilegeAttributes();
        $promoted = ! $created && $attributes && $user->wasChanged($attributes);
        $passwordChanged = ! $created && $user->wasChanged('password');
        $emailChanged = ! $created && $user->wasChanged('email');

        if (! $created && ! $promoted && ! $passwordChanged && ! $emailChanged) {
            return;
        }

        $role = $this->privileges->role($user);
        $what = match (true) {
            $created => 'New privileged account created',
            $promoted => 'Account promoted to ' . ($role ?? 'admin'),
            $passwordChanged => 'Privileged account password changed',
            default => 'Privileged account email changed',
        };

        $request = app()->runningInConsole() ? null : request();
        $this->alerter->record('admin-account', $what . ': ' . ($user->email ?? '#' . $user->getKey()), [
            'user_id' => $user->getKey(),
            'role' => $role,
            'changed' => array_keys($user->getChanges()),
            'by_user_id' => optional(auth()->user())->getAuthIdentifier(),
            'ip' => $request?->ip(),
            'url' => $request?->fullUrl(),
            'console' => app()->runningInConsole(),
        ], alert: true);
    }
}
