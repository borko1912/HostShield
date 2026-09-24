<p align="center"><img src="assets/logo.svg" width="72" alt=""></p>

<h1 align="center">HostShield</h1>

<p align="center"><b>Firewall, backups and malware scanner for sites on shared hosting — no root, no Docker, no monthly fee.</b></p>

<p align="center">
  <a href="https://github.com/borko1912/HostShield/actions"><img src="https://github.com/borko1912/HostShield/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/PHP-8.1%20%E2%80%93%208.4-777bb4" alt="PHP 8.1–8.4">
  <a href="https://github.com/sponsors/borko1912"><img src="https://img.shields.io/badge/sponsor-%E2%99%A5-ea4aaa" alt="Sponsor"></a>
</p>

<p align="center"><a href="README.bg.md">Български</a></p>

---

Your sites live on a cPanel / SPanel / Plesk / DirectAdmin account. You don't have root, so server firewalls and agents are out.
Security plugins protect one WordPress at a time — and die together with it when it gets hacked.

HostShield is a single small PHP app you upload once. It protects **every site in the hosting account** (WordPress, Laravel,
Joomla, Drupal, PrestaShop, OpenCart, Magento or plain PHP) from the outside: a firewall that runs before each site,
nightly backups with one-click restore, a file monitor that catches web shells, and a security audit with a grade.

It was built after the author's own sites were hacked again and again. It has been running in production on them since.

## What you get

| | |
|---|---|
| 🛡 **Firewall (WAF)** | Runs before every PHP request of every site. Stops SQL injection, XSS, path traversal, remote code execution, scanners and brute force. Bans repeat offenders (1 h → 2 h → 4 h … 7 days). Starts in **log-only mode** so you can mark false positives with one click before switching to blocking. |
| 🚫 **Stops web shells** | PHP can never run from upload folders. Optional **Lockdown**: only scripts you approved may run at all — a freshly uploaded shell simply doesn't execute. |
| 💾 **Backups** | Files + databases every night. Daily / weekly / monthly retention. Checksums verified before every restore. Copies to **S3, Backblaze B2, Cloudflare R2, Wasabi, MinIO or FTP**, and can pull a backup back from there after losing the server. |
| ⏪ **One-click restore** | Everything, files only, or database only. Takes a safety backup first, shows a maintenance page while it runs, removes files the attacker added. |
| 🔍 **Malware scanner** | Watches every code file and every upload. Signatures for common shells and obfuscation. **WordPress core and plugins are compared with the official wordpress.org checksums** — a single modified file is caught. Quarantine with undo. |
| 📋 **Security audit** | 20+ checks per site with an A–F grade: exposed `.env` / `.git` / backups, SSL expiry, HTTPS redirect, security headers, outdated WordPress, debug mode, weak config, world-writable files. Every problem comes with the fix. |
| 🔔 **Alerts** | Email (PHP mail or SMTP), Telegram, Discord, Slack or any webhook: site down, SSL expiring, suspicious code, failed backup, new login. |
| ⚙️ **Zero-config setup** | Web installer finds the sites in your account and reads each app's database credentials from its own config. No config files to edit. |
| 🌍 **English and Bulgarian** | Translations are one PHP file each — contributions welcome. |


## Install (5 minutes)

**Requirements:** PHP 8.1+ with `zip`, `mysqli`, `curl` (all standard on shared hosting). A cron job every minute.

1. **Download** the latest release zip from [Releases](https://github.com/borko1912/HostShield/releases).
2. **Create a subdomain** for the dashboard, e.g. `shield.example.com`, and **upload** the zip contents into its folder
   (hosting File Manager → Upload → Extract).
3. **Open** `https://shield.example.com` — the installer checks the server, picks a data folder outside the web root,
   creates your account and lists the sites it found. Click **Install**.
4. **Cron:** the dashboard shows the exact command for your server. Paste it into *Cron Jobs → every minute*.
5. On each site click **Enable firewall**, then **Back up now**. Turn on **2FA** in *Settings → Security*.

The setup checklist on the overview page walks you through the rest (alerts, off-site storage, switching the firewall to *Block*).

> The installer only runs within 24 hours of upload. If you extracted the files earlier, create an empty file named
> `install.unlock` next to `index.php` and reload.

## How it works

```
                       every PHP request
 visitor ──► site ──► auto_prepend_file ──► waf/firewall.php ──► block / log / pass ──► WordPress, Laravel …
                                                  │
                                                  ▼
 cron (every minute) ──► cron/worker.php ──► backups · restores · file scans · uptime · SSL · audit · alerts
                                                  │
 dashboard (index.php) ◄──────────────────────────┘      data folder (outside the web root):
                                                          settings.php · backups/ · logs/ · quarantine/
```

* The firewall is attached per site with one line (`auto_prepend_file`) in the site's `.user.ini` / `php.ini`
  (PHP-FPM, LiteSpeed) or `.htaccess` (Apache mod_php). The dashboard adds and removes it for you.
* **Fail-open:** if HostShield itself has a problem, your sites keep working.
* The firewall is fast: one small PHP file, rules cached by opcache, counters in APCu when available.
* Everything is plain files — no database of its own, no external service, no phone-home (only optional update checks
  against the GitHub API and checksum lookups on wordpress.org).

## Command line

```bash
php cron/worker.php --backup [site]                    # back up now
php cron/worker.php --restore <site> <backup> [all|files|db]
php cron/worker.php --scan [site]                      # full malware scan with report
php cron/worker.php --audit [site]                     # security grades
php cron/worker.php --accept <site>                    # approve files after your own deploy
php cron/worker.php --test-notify                      # test every alert channel
php cron/worker.php --status
```

## FAQ

**Does it replace Wordfence / Sucuri?**
For many sites, yes. Unlike a WordPress plugin, HostShield sits *outside* the sites it protects, covers every site in the
account (not only WordPress), and keeps working when a site is compromised. It does not stop network-level DDoS — put
Cloudflare's free plan in front for that and add its IP ranges under *Trusted proxies*.

**Will it break my site?**
It starts in log-only mode. Watch the events for a few days, click *Not an attack* on anything legitimate, then switch to
*Block*. If the firewall ever fails internally, requests pass through.

**Where are my backups?** In the data folder you chose (outside the web root), and in your S3/FTP storage if configured.
They are ordinary `.zip` and `.sql.gz` files — you can restore them by hand without HostShield.

**My host deploys from Git and overwrites `.user.ini`.** Add the firewall line to your repository; the dashboard shows it.
After a deploy, click *Approve changes* on the Files tab (or run `--accept`).

**Nginx?** Deny access to `lib/`, `cron/`, `waf/`, `app/`, `lang/` and `config.php`; see [docs/nginx.md](docs/nginx.md).

## Support the project

HostShield is free and open source. If it saved your site — or your weekend — please consider
**[sponsoring on GitHub](https://github.com/sponsors/borko1912)**. Sponsorships fund testing on more hosting providers and the
roadmap below. A ⭐ helps others find it, too.

**Roadmap:** one dashboard for several hosting accounts · encrypted off-site backups · country blocking · 2FA for
WordPress logins · one-click updates · more languages.

## Contributing

Bug reports, false positives and translations are very welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues: please report privately, see [SECURITY.md](SECURITY.md).

```bash
php tests/run.php            # unit tests (no dependencies)
bash tests/e2e/run.sh        # full end-to-end test in Docker: WordPress, MariaDB, MinIO
```

## License

[AGPL-3.0](LICENSE) © 2026 borko1912 and contributors. You may use, modify and share HostShield freely; if you offer a modified version as a
service, you must publish your changes under the same license.
