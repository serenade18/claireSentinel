<?php

return [

    'enabled' => env('SENTINEL_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Alerts
    |--------------------------------------------------------------------------
    | Everything is written to storage/logs/sentinel-*.log. When an address is
    | set (comma-separate several), alerts are also mailed, at most one mail per
    | alert type per `alert_throttle_minutes`.
    */
    'alert_email' => env('SENTINEL_ALERT_EMAIL'),
    'alert_throttle_minutes' => 15,
    'log_days' => 90,

    /*
    |--------------------------------------------------------------------------
    | Firewall
    |--------------------------------------------------------------------------
    */
    'firewall' => [
        // Push the firewall onto the global middleware stack so it also sees
        // requests that match no route (probes) and every upload. Set to false
        // to apply the `sentinel.firewall` middleware alias yourself.
        'global' => env('SENTINEL_FIREWALL_GLOBAL', true),

        // IPs that are never blocked or banned (your office, uptime monitor...).
        'allow_ips' => array_values(array_filter(array_map('trim', explode(',', (string) env('SENTINEL_ALLOW_IPS', ''))))),

        // Paths (regex, matched against the path without the leading slash) that
        // only an attacker would request, such as backdoors known to exist in
        // your codebase or its CMS. Any hit bans the IP immediately.
        'honeypot_paths' => [
            '#(^|/)(shell|wso|c99|r57|b374k|alfa|alfa-rex|priv8)\.php$#i',
            '#(^|/)wp-cron\.zip$#i',
        ],

        // Generic probes. Each hit counts as one strike.
        'blocked_paths' => [
            // Direct requests for script files (Laravel serves everything through index.php).
            '#^(?!index\.php$)(.*/)?[^/]+\.(php[0-9]*|pht|phtml|phar|phps|inc|cgi|pl|py|sh|asp|aspx|jsp)(/|\.|$)#i',
            // Dotfiles and VCS metadata.
            '#(^|/)\.(env|git|svn|hg|htaccess|htpasswd|user\.ini|DS_Store)#i',
            // WordPress scanners.
            '#(^|/)(wp-admin|wp-login|wp-content|wp-includes|xmlrpc)(\.php|/|$)#i',
            // Folders that are never routes.
            '#^(vendor|node_modules|cgi-bin)/#i',
            // Dumps and editor/backup files.
            '#\.(sql|sql\.gz|bak|old|orig|swp)$#i',
        ],

        // Paths (regex) whose request *input* is not inspected (payment webhooks
        // that post opaque payloads, rich-text editors you trust...).
        'skip_input_inspection' => [
            // '#^api/webhooks/#',
        ],

        // Requests from these ranges are still blocked when malicious, but the
        // address is never banned. Behind a CDN without TrustProxies configured,
        // banning the edge IP would lock out every visitor behind it.
        // Default: Cloudflare edge ranges and loopback.
        'never_ban_ranges' => [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
            '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
            '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
            '127.0.0.1', '::1',
        ],

        // Strikes before an automatic ban, counted within `strike_window_minutes`.
        'max_strikes' => 5,
        'strike_window_minutes' => 10,
        'ban_minutes' => 24 * 60,

        // Cache store for bans and strikes (null = the default store). Use a
        // shared store (redis, database) when running more than one web server.
        'cache_store' => env('SENTINEL_CACHE_STORE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Upload inspection
    |--------------------------------------------------------------------------
    */
    'uploads' => [
        'blocked_extensions' => [
            'php', 'php3', 'php4', 'php5', 'php56', 'php6', 'php7', 'php74', 'php8', 'pht', 'phtml',
            'phar', 'phps', 'inc', 'cgi', 'pl', 'py', 'sh', 'bash', 'exe', 'elf', 'so', 'dll',
            'asp', 'aspx', 'jsp', 'shtml', 'htaccess', 'htpasswd', 'ini', 'suspected',
        ],
        'blocked_filenames' => ['.htaccess', '.htpasswd', '.user.ini', 'php.ini', 'web.config'],

        // Some apps legitimately accept archives that contain PHP (plugin, addon
        // or update installers). They are accepted only while this flag is on,
        // only on the paths below, and only from a privileged user (see `admin`).
        // Turn it on to install, then off again.
        'allow_code_archives' => env('SENTINEL_ALLOW_CODE_UPLOADS', false),
        'code_archive_paths' => [
            // '#^admin/plugins/install$#',
        ],

        'max_scan_bytes' => 20 * 1024 * 1024,
        'max_archive_entries' => 5000,
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin activity monitor
    |--------------------------------------------------------------------------
    | Alerts on privileged logins, new privileged accounts, promotions, and
    | password or email changes on privileged accounts. A user is privileged
    | when any of the checks below says so.
    */
    'admin' => [
        'enabled' => env('SENTINEL_ADMIN_MONITOR', true),

        // null = the model of the `users` auth provider.
        'user_model' => null,

        // A column holding a role name, e.g. 'role' or 'user_type'.
        'role_attribute' => null,
        'privileged_roles' => ['admin', 'administrator', 'super-admin', 'superadmin', 'staff'],

        // Boolean columns that mark an admin.
        'flag_attributes' => ['is_admin', 'is_super_admin'],

        // With spatie/laravel-permission: hasAnyRole(privileged_roles).
        'spatie_roles' => true,

        // A Gate ability that only admins have, e.g. 'viewNova'.
        'gate' => null,

        // A class implementing ClaireSentinel\Contracts\DeterminesPrivilege,
        // for anything the checks above can't express.
        'resolver' => null,

        'alert_on_login' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Integrity scanner
    |--------------------------------------------------------------------------
    | `php artisan sentinel:scan`, scheduled per `schedule`. Paths are relative
    | to base_path().
    */
    'integrity' => [
        'baseline_path' => storage_path('app/sentinel/baseline.json'),
        'quarantine_path' => storage_path('app/sentinel/quarantine'),

        // "hourly", "daily", a cron expression, or empty to not schedule it.
        'schedule' => env('SENTINEL_SCAN_SCHEDULE', 'hourly'),
        // Let the scheduled scan restore guards and quarantine attacker files.
        'schedule_fix' => env('SENTINEL_SCAN_FIX', true),

        // Hashed into the baseline; any change, addition or removal is reported.
        'watch' => [
            'app', 'bootstrap/app.php', 'config', 'routes', 'resources/views', 'database/migrations',
            'vendor', 'public/index.php', 'artisan', 'composer.json', 'composer.lock',
            '.htaccess', 'public/.htaccess',
        ],
        'watch_exclude' => ['#^vendor/composer/installed\.(json|php)$#'],

        // Searched for malware signatures and stray scripts on every scan.
        'scan' => ['.'],
        'scan_exclude' => [
            '#^(node_modules|\.git|storage/app/sentinel|storage/debugbar)(/|$)#',
            '#^storage/logs/[^/]+\.log$#',
        ],

        // Hidden directories that are expected (any other is reported).
        'hidden_dirs_allowed' => [
            '.git', '.github', '.gitlab', '.well-known', '.idea', '.vscode', '.fleet',
            '.ddev', '.devcontainer', '.docker', '.circleci', '.husky',
        ],

        // Zip archives here are opened and checked for scripts and path traversal.
        'inspect_archives_in' => ['public', 'storage/app/public'],

        // The only script files allowed anywhere under public/.
        'public_scripts_allowed' => ['public/index.php'],

        // The only .htaccess files allowed in the project (guard files below are
        // always allowed).
        'htaccess_allowed' => ['.htaccess', 'public/.htaccess'],

        // Guard files that stop Apache running scripts in upload folders. A guard
        // is only enforced when its folder exists; `sentinel:scan --fix` restores
        // missing or altered ones from resources/stubs:
        //   no-exec.htaccess  serve files, never run scripts
        //   deny-all.htaccess no web access at all
        'guards' => [
            'storage/app/public/.htaccess' => 'no-exec.htaccess',
            'public/uploads/.htaccess' => 'no-exec.htaccess',
        ],

        // New script files found here are moved to quarantine by --fix.
        'auto_quarantine' => ['public', 'storage/app/public', 'storage/framework/cache', 'bootstrap/cache'],

        'max_file_bytes' => 5 * 1024 * 1024,
    ],
];
