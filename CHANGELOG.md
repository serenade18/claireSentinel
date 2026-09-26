# Changelog

## 1.0.0 - 2026-09-26

First public release as `serenade18/clairesentinel`. Extracted from the security package of a compromised Laravel shop and made generic.

- Works with Laravel 10, 11, 12 and 13, tested with Orchestra Testbench.
- Namespace is `ClaireSentinel\`.
- Admin detection works on any app: a role column, boolean flag columns, spatie/laravel-permission roles, a Gate ability, or a custom `DeterminesPrivilege` resolver. The user model defaults to the auth provider's.
- Installer archives that contain code are allowed only when `SENTINEL_ALLOW_CODE_UPLOADS` is on, on the configured paths, and for a privileged user. The user is checked after the route's session and auth middleware, so the rule now works; it used to run before the session started. The flag is read from config, so it also works with `config:cache`.
- Admin alerts use Eloquent's `created` and `updated` events. Promoting a user on the same model instance that created it is now reported correctly.
- The firewall can run as global middleware or through the `sentinel.firewall` alias. Bans can use a dedicated cache store.
- Generic defaults: app-specific honeypots and blocked folders are no longer built in. Guards cover `storage/app/public` and `public/uploads`, and apply only where the folder exists. The hidden-folder allowlist is configurable.
- Stubs renamed to `no-exec.htaccess` and `deny-all.htaccess`.
