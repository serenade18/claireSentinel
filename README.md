# ClaireSentinel

[![Tests](https://github.com/serenade18/claireSentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/serenade18/claireSentinel/actions/workflows/tests.yml)

A drop-in security layer for Laravel 10, 11, 12 and 13. It was built after a real compromise of a Laravel shop
(webshells in upload folders, a backdoored `index.php`, a crypto miner and rogue `.htaccess` files) and stops each of those techniques:

| Component | What it does |
|---|---|
| **Firewall** (global middleware) | Blocks direct `*.php` hits, `.env`/`.git`/`wp-*` probes, `zip://`/`phar://`/`php://` wrappers and PHP code in request input. Honeypot paths ban an IP at once; repeat offenders are banned after 5 strikes in 10 minutes, for 24 hours. |
| **Upload inspector** | Rejects any upload containing PHP (including image polyglots), dangerous or double extensions (`x.php.jpg`), `.htaccess`/`.user.ini`, executables, and zips with `../` paths (Zip Slip), scripts, or PHP inside. |
| **Admin monitor** | Alerts on every admin login, new admin accounts, promotions to admin, and admin password or email changes. |
| **Integrity scanner** | An HMAC-signed baseline of your code and `vendor/`. It reports changed or added files, scripts under `public/`, webshell signatures, ELF binaries (miners), rogue `.htaccess` files and unexpected hidden folders. It can quarantine attacker files and restore the no-exec guards on upload folders. |

Everything is logged to `storage/logs/sentinel-YYYY-MM-DD.log`. Alerts are emailed when `SENTINEL_ALERT_EMAIL` is set, at most one per alert type every 15 minutes.

## Requirements

- PHP 8.1+ (Laravel 13 needs 8.3+)
- Laravel 10, 11, 12 or 13
- `ext-zip`, to inspect archives

## Installation

```bash
composer require serenade18/clairesentinel
```

Package discovery registers the service provider. The firewall is on as soon as the package is installed.

Then:

1. Set where alerts go (and make sure your mail settings actually send):
   ```dotenv
   SENTINEL_ALERT_EMAIL=you@example.com
   ```
2. Make sure the Laravel scheduler runs every minute. It runs `sentinel:scan --fix` hourly:
   ```
   * * * * * cd /path/to/app && php artisan schedule:run >> /dev/null 2>&1
   ```
3. Once you have confirmed the deployed code is clean, record the baseline:
   ```bash
   php artisan sentinel:baseline
   ```

To customise the settings, publish the config:

```bash
php artisan vendor:publish --tag=sentinel-config
```

## Day-to-day

| Task | Command |
|---|---|
| Manual scan | `php artisan sentinel:scan` (`--json` for machine output; exits 1 on critical findings) |
| Scan and auto-remediate | `php artisan sentinel:scan --fix` |
| After a legitimate deploy or `composer update` | `php artisan sentinel:baseline --force` |
| Unban an IP | `php artisan sentinel:unban 1.2.3.4` |
| Never block an IP | `SENTINEL_ALLOW_IPS=1.2.3.4,5.6.7.8` |

**What `--fix` moves** into `storage/app/sentinel/quarantine/<timestamp>/`: new files with malicious evidence, such as webshells, scripts under `public/`, miner binaries, rogue `.htaccess` files and dangerous zips. The folder is read-only and includes a `manifest.txt` of SHA-256 hashes.
**It never moves a file that is in the baseline.** A backdoored `public/index.php` or controller is reported for a human to restore. Moving it automatically would take the site down.

## Configuration

These are the settings you're most likely to change. Everything is documented in [`config/sentinel.php`](config/sentinel.php).

### Telling Sentinel who your admins are

The admin monitor and the code-upload rule need to know which users are privileged. A user counts as an admin when **any** of these enabled checks says so:

```php
'admin' => [
    'role_attribute'   => 'role',                // column holding a role name…
    'privileged_roles' => ['admin', 'staff'],    // …and the values that count
    'flag_attributes'  => ['is_admin'],          // boolean columns
    'spatie_roles'     => true,                  // spatie/laravel-permission: hasAnyRole(privileged_roles)
    'gate'             => null,                  // a Gate ability only admins have, e.g. 'viewNova'
    'resolver'         => null,                  // your own class (see below)
],
```

For anything else, implement `ClaireSentinel\Contracts\DeterminesPrivilege` and set `resolver` to its class name:

```php
class TeamOwnersAreAdmins implements DeterminesPrivilege
{
    public function isPrivileged(Authenticatable $user): bool { return $user->ownsCurrentTeam(); }
    public function role(Authenticatable $user): ?string { return 'owner'; }
}
```

The user model defaults to your `auth.providers.users.model`.

### Honeypot paths

Add URLs that only an attacker would request, such as a backdoor that used to exist in your code or that your CMS is known to ship. A single hit bans the IP:

```php
'firewall' => [
    'honeypot_paths' => [
        '#^import-data$#i',
        '#^system/sitemap-item-add(/|$)#i',
    ],
],
```

### Plugin, addon and update installers

Archives that contain PHP are rejected by default. If your app installs plugins from uploaded zips, allow them only on the installer route and only while you're installing:

```php
'uploads' => [
    'allow_code_archives' => env('SENTINEL_ALLOW_CODE_UPLOADS', false),
    'code_archive_paths'  => ['#^admin/addons$#'],
],
```

With the flag on, such an archive is accepted only from a privileged user, and every accepted upload triggers an alert. Path traversal inside the archive is never allowed.
Turn the flag on, install, turn it off, then check the new code and run `sentinel:baseline --force`.

### Upload folder guards (Apache)

On Apache, a `.htaccess` in each upload folder stops uploaded scripts from running. The defaults cover `storage/app/public` (served via `public/storage`) and `public/uploads`. A guard is only applied when its folder exists, and `--fix` restores a guard that has been removed or altered:

```php
'integrity' => [
    'guards' => [
        'storage/app/public/.htaccess' => 'no-exec.htaccess', // serve files, never run scripts
        'public/addons/.htaccess'      => 'deny-all.htaccess', // no web access at all
    ],
],
```

On Nginx, add an equivalent rule to your server block, for example:
`location ~* ^/(storage|uploads)/.*\.(php|phtml|phar)$ { deny all; }`

### Only the firewall, as route middleware

```dotenv
SENTINEL_FIREWALL_GLOBAL=false
```

Then apply the `sentinel.firewall` middleware to the routes or groups you choose. Running it globally is recommended, though: probes rarely hit real routes.

### Multiple servers

Bans and strikes live in the cache. Set `SENTINEL_CACHE_STORE=redis` (or `database`) so that every web server shares them.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SENTINEL_ENABLED` | `true` | Master switch |
| `SENTINEL_ALERT_EMAIL` | none | Comma-separated alert recipients |
| `SENTINEL_ALLOW_IPS` | none | IPs that are never blocked |
| `SENTINEL_FIREWALL_GLOBAL` | `true` | Register the firewall as global middleware |
| `SENTINEL_CACHE_STORE` | default store | Cache store for bans and strikes |
| `SENTINEL_ALLOW_CODE_UPLOADS` | `false` | Temporarily allow installer archives containing PHP |
| `SENTINEL_ADMIN_MONITOR` | `true` | Admin login and account alerts |
| `SENTINEL_SCAN_SCHEDULE` | `hourly` | `hourly`, `daily`, a cron expression, or empty to disable |
| `SENTINEL_SCAN_FIX` | `true` | Scheduled scans also restore guards and quarantine files |

## Limits

- An attacker who already has code execution and your `APP_KEY` can re-sign the baseline. After a breach, rotate `APP_KEY` before you run `sentinel:baseline`. Alert emails leave an out-of-band trail either way.
- The firewall only sees requests that reach Laravel. Files that the web server serves directly have to be protected by server rules; the guards above cover the upload folders.
- Behind a CDN, configure `TrustProxies` so `$request->ip()` is the visitor's IP. Cloudflare's edge ranges are never banned (`never_ban_ranges`), so a misconfiguration can't lock out every visitor.
- Role changes made only through pivot tables (such as `spatie/laravel-permission`'s `assignRole`) don't fire model events, so promotions done that way aren't alerted. Logins are.

## Testing

```bash
composer install
composer test
```

The scanner test replays the 2026 compromise that this package was built from.

## License

MIT. See [LICENSE](LICENSE).
