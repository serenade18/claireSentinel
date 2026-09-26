<?php

namespace ClaireSentinel\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Custom rule for which users count as admins (config: sentinel.admin.resolver).
 */
interface DeterminesPrivilege
{
    /** True when $user can administer the application. */
    public function isPrivileged(Authenticatable $user): bool;

    /** A short label for alerts, e.g. "admin" (null when unknown). */
    public function role(Authenticatable $user): ?string;
}
