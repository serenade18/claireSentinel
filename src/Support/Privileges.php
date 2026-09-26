<?php

namespace ClaireSentinel\Support;

use ClaireSentinel\Contracts\DeterminesPrivilege;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Gate;
use Throwable;

/**
 * Decides whether a user is privileged, using the checks enabled in sentinel.admin.
 */
class Privileges
{
    public function isPrivileged(mixed $user): bool
    {
        if (! $user instanceof Authenticatable) {
            return false;
        }

        if ($resolver = $this->resolver()) {
            return $resolver->isPrivileged($user);
        }

        $roles = $this->privilegedRoles();

        if (($attr = config('sentinel.admin.role_attribute')) && in_array($this->attribute($user, $attr), $roles, true)) {
            return true;
        }

        foreach ((array) config('sentinel.admin.flag_attributes', []) as $flag) {
            if (filter_var($this->attribute($user, $flag), FILTER_VALIDATE_BOOLEAN)) {
                return true;
            }
        }

        if (config('sentinel.admin.spatie_roles', true) && method_exists($user, 'hasAnyRole') && $roles) {
            try {
                if ($user->hasAnyRole($roles)) {
                    return true;
                }
            } catch (Throwable) {
                // Roles table missing or guard mismatch: treat as not privileged.
            }
        }

        if ($ability = config('sentinel.admin.gate')) {
            try {
                return Gate::forUser($user)->allows($ability);
            } catch (Throwable) {
                return false;
            }
        }

        return false;
    }

    /** Label used in alerts. */
    public function role(mixed $user): ?string
    {
        if (! $user instanceof Authenticatable) {
            return null;
        }
        if ($resolver = $this->resolver()) {
            return $resolver->role($user);
        }
        if ($attr = config('sentinel.admin.role_attribute')) {
            $role = $this->attribute($user, $attr);
            if (is_string($role) && $role !== '') {
                return $role;
            }
        }

        return $this->isPrivileged($user) ? 'admin' : null;
    }

    /** Model attributes whose change can make a user privileged. */
    public function privilegeAttributes(): array
    {
        return array_values(array_filter(array_merge(
            [config('sentinel.admin.role_attribute')],
            (array) config('sentinel.admin.flag_attributes', [])
        )));
    }

    private function privilegedRoles(): array
    {
        return array_values((array) config('sentinel.admin.privileged_roles', []));
    }

    private function attribute(Authenticatable $user, string $name): mixed
    {
        return method_exists($user, 'getAttribute') ? $user->getAttribute($name) : ($user->{$name} ?? null);
    }

    private function resolver(): ?DeterminesPrivilege
    {
        $class = config('sentinel.admin.resolver');

        return $class ? app($class) : null;
    }
}
