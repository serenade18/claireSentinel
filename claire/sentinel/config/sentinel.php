<?php

return [

    'enabled' => env('SENTINEL_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Alerts
    |--------------------------------------------------------------------------
    | Everything is written to storage/logs/sentinel-*.log. When an address is
    | set, alerts are also mailed (at most one mail per alert type per
    | `alert_throttle_minutes`).
    */
    'alert_email' => env('SENTINEL_ALERT_EMAIL'),
    'alert_throttle_minutes' => 15,

    /*
    |--------------------------------------------------------------------------
    | Firewall
    |--------------------------------------------------------------------------
    */
    'firewall' => [
        // IPs that are never blocked or banned (your office, uptime monitor...).
        'allow_ips' => array_filter(explode(',', (string) env('SENTINEL_ALLOW_IPS', ''))),

        // Requests to these paths are attacks on backdoors that existed in this
        // codebase. Any hit bans the IP immediately.
        'honeypot_paths' => [
            '#^system/sitemap-item-add(/|$)#i',
            '#^import-data$#i',
            '#^translation-check(/|$)#i',
            '#^checkout-payment-detail$#i',
            '#^customer-products/admin$#i',
            '#^compare/details(/|$)#i',
            '#^vogue-pay/callback$#i',
            '#(^|/)wp-cron\.zip$#i',
        ],

        // Generic probes. Each hit counts as one strike.
        'blocked_paths' => [
            '#^(?!index\.php$)(.*/)?[^/]+\.(php[0-9]*|pht|phtml|phar|phps|inc|cgi|pl|py|sh|asp|aspx|jsp)(/|\.|$)#i',
            '#(^|/)\.(env|git|svn|hg|htaccess|htpasswd|user\.ini|DS_Store)#i',
            '#(^|/)(wp-admin|wp-login|wp-content|wp-includes|xmlrpc)(\.php|/|$)#i',
            '#^(vendor|storage|bootstrap|config|app|database|routes|temp|cgi-bin|node_modules)/#i',
            '#\.(sql|bak|old|orig|swp|log)$#i',
        ],

        // Paths (regex) whose request *input* is not inspected (payment webhooks
        // that post opaque payloads, rich-text editors you trust, etc.).
        'skip_input_inspection' => [
            // '#^api/callback$#',
        ],

        // Requests from these ranges are still blocked when malicious, but the
        // address is never banned: behind a CDN (Cloudflare) without TrustProxies
        // configured, banning the edge IP would lock out every visitor behind it.
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

        // Archives containing PHP are normal for addon/update packages. They are
        // accepted only on these paths, only for an admin, and only while
        // ALLOW_CODE_UPLOADS=true is set in .env.
        'code_archive_paths' => ['#^admin/addons$#', '#^aiz-uploader/upload$#'],

        'max_scan_bytes' => 20 * 1024 * 1024,
        'max_archive_entries' => 5000,
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin activity monitor
    |--------------------------------------------------------------------------
    */
    'admin' => [
        'user_model' => \App\Models\User::class,
        'role_attribute' => 'user_type',
        'privileged_roles' => ['admin', 'staff'],
        'alert_on_login' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Integrity scanner (php artisan sentinel:scan, runs hourly via scheduler)
    |--------------------------------------------------------------------------
    | Paths are relative to base_path().
    */
    'integrity' => [
        'baseline_path' => storage_path('app/sentinel/baseline.json'),
        'quarantine_path' => storage_path('app/sentinel/quarantine'),
        'schedule' => env('SENTINEL_SCAN_SCHEDULE', 'hourly'), // cron expression or "hourly"/"daily"; empty = off

        // Hashed into the baseline; any change / addition / removal is reported.
        'watch' => [
            'app', 'bootstrap/app.php', 'config', 'routes', 'resources/views', 'database/migrations',
            'packages', 'vendor', 'public/index.php', 'artisan', 'composer.json',
            '.htaccess', 'public/.htaccess', 'public/uploads/.htaccess', 'public/addons/.htaccess',
        ],
        'watch_exclude' => ['#^vendor/composer/installed\.(json|php)$#'],

        // Searched for malware signatures and stray scripts on every scan.
        'scan' => ['.'],
        'scan_exclude' => ['#^(node_modules|\.git|storage/app/sentinel|storage/debugbar)(/|$)#', '#^storage/logs/[^/]+\.log$#'],

        // Zip archives here are opened and checked for scripts / path traversal.
        'inspect_archives_in' => ['public', 'temp'],

        // The only script files allowed anywhere under public/.
        'public_scripts_allowed' => ['public/index.php'],

        // The only .htaccess files allowed in the project.
        'htaccess_allowed' => [
            '.htaccess', 'public/.htaccess', 'public/uploads/.htaccess', 'public/addons/.htaccess', 'resources/.htaccess',
        ],

        // Guard files that must exist; `sentinel:scan --fix` (and the scheduled
        // scan) restores them from the package stubs.
        'guards' => [
            'public/uploads/.htaccess' => 'uploads.htaccess',
            'public/addons/.htaccess' => 'addons.htaccess',
        ],

        // New script files found here are moved to quarantine by --fix.
        'auto_quarantine' => ['public', 'temp', 'storage/framework/cache', 'bootstrap/cache'],

        'max_file_bytes' => 5 * 1024 * 1024,
    ],
];
