<?php

namespace ClaireSentinel\Tests\Fixtures;

use ClaireSentinel\Contracts\DeterminesPrivilege;
use Illuminate\Contracts\Auth\Authenticatable;

class OnlyIdSevenIsAdmin implements DeterminesPrivilege
{
    public function isPrivileged(Authenticatable $user): bool
    {
        return (int) $user->getAuthIdentifier() === 7;
    }

    public function role(Authenticatable $user): ?string
    {
        return $this->isPrivileged($user) ? 'owner' : null;
    }
}
