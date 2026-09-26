# claire/sentinel

Security layer for the claire.solar Laravel shop, built after the September 2026 compromise.
It targets the techniques used in that attack.

| Component | What it does |
|---|---|
| **Firewall** (global middleware) | Blocks the old CMS backdoor URLs (an instant 24h IP ban), direct `*.php` hits, `.env`/`.git`/`wp-*` probes, and `zip://`/`phar://`/`php://` wrappers or PHP code in request input. Repeat offenders are banned (5 strikes in 10 min → 24h). |
| **Upload inspector** | Rejects any upload containing PHP (including image polyglots), dangerous or double extensions (`x.php.jpg`), `.htaccess`/`.user.ini`, and zips with `../` paths (Zip Slip), scripts, or PHP inside. |
| **Admin monitor** | Alerts on every admin/staff login, new admin accounts, promotion to admin, and admin password or email changes. |
| **Integrity scanner** | An HMAC-signed baseline of the code and `vendor/`. It reports changed or added files, scripts under `public/`, webshell signatures, ELF binaries (miners), rogue `.htaccess` files, hidden directories, and dangerous zips. It restores the upload no-exec guards. |

Everything is logged to `storage/logs/sentinel-YYYY-MM-DD.log`. Alerts are emailed when `SENTINEL_ALERT_EMAIL` is set (at most one email per alert type every 15 minutes).

## Installation (already done in this app)

Sentinel is installed like any other Composer package: the code runs from `vendor/claire/sentinel`, and Laravel's package discovery registers `SentinelServiceProvider`. There is no entry in `config/app.php`.

`packages/claire/sentinel` is the source. The root `composer.json` points at it with a path repository (`"symlink": false`, so Composer copies it into `vendor/` and doesn't symlink it) and requires `claire/sentinel: ^1.0`.

After editing the source, copy it into `vendor/` with `composer update claire/sentinel`. Only do that once `composer.lock` matches `vendor/` again; until then it would also change other packages. Instead, copy the folder over `vendor/claire/sentinel` and run `composer dump-autoload -o`.
## Server setup (required)

1. Upload `vendor/` as usual. It must include `vendor/claire/sentinel`, `vendor/composer/` and `bootstrap/cache/packages.php`, or run `php artisan package:discover` on the server.
2. Set `SENTINEL_ALERT_EMAIL=you@example.com` in `.env`. Make sure the SMTP settings actually send mail.
3. Add the Laravel scheduler cron in cPanel (Cron Jobs), every minute:
   `* * * * * cd /home/claireso/public_html && php artisan schedule:run >> /dev/null 2>&1`
   This runs `sentinel:scan --fix` hourly.
4. **After** rotating `APP_KEY` and confirming the deployed code is clean:
   `php artisan sentinel:baseline`

## Day-to-day

| Task | Command |
|---|---|
| Manual scan | `php artisan sentinel:scan` (`--json` for machine output) |
| Scan and auto-remediate | `php artisan sentinel:scan --fix` |
| After a legitimate deploy, CMS update or addon install | `php artisan sentinel:baseline --force` |
| Unban an IP | `php artisan sentinel:unban 1.2.3.4` |
| Never block an IP | `SENTINEL_ALLOW_IPS=1.2.3.4,5.6.7.8` |
| Publish the config to customise it | `php artisan vendor:publish --tag=sentinel-config` |

**What `--fix` moves** to `storage/app/sentinel/quarantine/<timestamp>/` (read-only, with a `manifest.txt` of SHA-256 hashes):
new files with malicious evidence (webshells, scripts under `public/`, miner binaries, rogue `.htaccess` files, dangerous zips).
**It never moves a file in the baseline.** A backdoored `public/index.php` or controller is reported, and a human restores it. Moving it automatically would take the site down.

## Addon and CMS updates

Addon and update zips contain PHP, so they are rejected unless all of these hold:
`ALLOW_CODE_UPLOADS=true` in `.env`, the user is an admin, and the upload goes to `admin/addons` or `aiz-uploader/upload`.
Turn the flag on, install, turn it off, then check the new code for backdoors like `== "bad"` and hidden login routes, and run `sentinel:baseline --force`.

## Tests

```
php -n -d memory_limit=1G vendor/bin/phpunit -c vendor/claire/sentinel/phpunit.xml
```
`-n` works around an OPcache crash in PHP 8.4 CLI on macOS. The scanner test replays the September 2026 attack.

## Limits

- An attacker who already has code execution and your `APP_KEY` can re-sign the baseline, so rotate `APP_KEY` after the breach.
  Alert emails leave an out-of-band trail either way.
- The firewall only sees requests that reach Laravel. Direct hits on files Apache serves itself are covered by the `.htaccess` rules.
- Behind a CDN, set `TrustProxies` correctly. Cloudflare edge IPs are never banned (`never_ban_ranges`), so a misconfiguration can't lock out all visitors.
