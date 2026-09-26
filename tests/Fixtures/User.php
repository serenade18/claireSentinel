<?php

namespace ClaireSentinel\Tests\Fixtures;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $table = 'users';

    protected $guarded = [];

    protected $casts = ['is_admin' => 'boolean'];
}
