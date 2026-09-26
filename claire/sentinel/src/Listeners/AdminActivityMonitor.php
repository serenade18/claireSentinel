<?php

namespace Claire\Sentinel\Listeners;

use Claire\Sentinel\Support\Alerter;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\Eloquent\Model;

/**
 * Alerts on privileged logins and on accounts gaining admin/staff rights,
 * the two things an attacker needs to install addons or edit settings.
 */
class AdminActivityMonitor
{
    public function __construct(private Alerter $alerter)
    {
    }

    public function onLogin(Login $event): void
    {
        if (! config('sentinel.admin.alert_on_login', true) || ! $this->isPrivileged($event->user)) {
            return;
        }

        $request = request();
        $this->alerter->record('admin-login', 'Privileged login: ' . ($event->user->email ?? ('#' . $event->user->getAuthIdentifier())), [
            'user_id' => $event->user->getAuthIdentifier(),
            'role' => $this->role($event->user),
            'ip' => $request?->ip(),
            'user_agent' => $request?->userAgent(),
            'url' => $request?->fullUrl(),
        ], alert: true);
    }

    public function onSaved(Model $user): void
    {
        $roleAttr = config('sentinel.admin.role_attribute', 'user_type');
        $becamePrivileged = $this->isPrivileged($user)
            && ($user->wasRecentlyCreated || $user->wasChanged($roleAttr));
        $privilegedPasswordChange = $this->isPrivileged($user) && ! $user->wasRecentlyCreated && $user->wasChanged('password');
        $privilegedEmailChange = $this->isPrivileged($user) && ! $user->wasRecentlyCreated && $user->wasChanged('email');

        if (! $becamePrivileged && ! $privilegedPasswordChange && ! $privilegedEmailChange) {
            return;
        }

        $what = $becamePrivileged
            ? ($user->wasRecentlyCreated ? 'New privileged account created' : 'Account promoted to ' . $this->role($user))
            : ($privilegedPasswordChange ? 'Privileged account password changed' : 'Privileged account email changed');

        $request = app()->runningInConsole() ? null : request();
        $this->alerter->record('admin-account', $what . ': ' . ($user->email ?? '#' . $user->getKey()), [
            'user_id' => $user->getKey(),
            'role' => $this->role($user),
            'changed' => array_keys($user->getChanges()),
            'by_user_id' => optional(auth()->user())->getAuthIdentifier(),
            'ip' => $request?->ip(),
            'url' => $request?->fullUrl(),
            'console' => app()->runningInConsole(),
        ], alert: true);
    }

    private function role($user): ?string
    {
        return $user->{config('sentinel.admin.role_attribute', 'user_type')} ?? null;
    }

    private function isPrivileged($user): bool
    {
        return in_array($this->role($user), (array) config('sentinel.admin.privileged_roles', ['admin', 'staff']), true);
    }
}
