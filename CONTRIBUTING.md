# Contributing to HostShield

Thank you for helping! The most useful contributions right now:

* **False positives.** If the firewall flagged a normal request, open an issue with the rule id, the path and the site
  platform (the event id from the dashboard helps). Please remove personal data from the request first.
* **Hosting reports.** "Works on host X with PHP Y" (or doesn't) helps everyone. Include the panel (cPanel, SPanel, Plesk,
  DirectAdmin), how PHP runs (FPM, LiteSpeed, mod_php) and whether the command-line or the web cron worked.
* **Translations.** Copy `lang/bg.php` to `lang/<code>.php`, translate the values (keep `%s` / `%d` in the same order), and
  add the language to `SHIELD_LANGUAGES` in `lib/i18n.php`.

## Development

No build step and no runtime dependencies. PHP 8.1+ is all you need.

```bash
php tests/run.php          # unit tests
bash tests/e2e/run.sh      # end-to-end test: WordPress + MariaDB + S3 in Docker
php -S 127.0.0.1:8088      # dashboard at http://127.0.0.1:8088 (the installer runs on first visit)
```

Code style: small procedural PHP files, `shield_` prefix for functions, strict types, every user-visible string wrapped in
`__()`. The firewall (`waf/`) must never throw into the protected site: keep it fail-open.

Pull requests: one topic per PR, with a test when it changes behaviour, and a line in `CHANGELOG.md` under *Unreleased*.
