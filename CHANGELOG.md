# Changelog

## 2.2.1

* Fix site settings saves by posting to the explicit site URL, preserving the site key for backup/database changes.
* Fix nested site settings POST data being mistaken for an invalid site key.
* Off-site S3: the endpoint may be typed without `https://` (it is added). Hosting firewalls (ModSecurity) answered
  403 to saving the backup settings when the field held `https://` plus another domain.
* "Detect database from app config" also reads plain PHP apps: `config.local.php`, `config/db.php`, `config.php`,
  `db_connect.php` … (return arrays, `define()`, `$db_*` variables, literal `new PDO()` / `new mysqli()`).

## 2.2.0

Nothing the dashboard can see is left without a backup:

* Every database visible to the dashboard's database user (or to a site's own user) that no site lists is dumped
  every night under "Other databases" — same retention, checksum verification and off-site copy as the sites.
* Overview: each site card shows which databases its last backup holds ("NONE — files only" in red), and an
  "Other databases" card lists the extra ones with their last backup and download links.
* `php cron/worker.php --backup _databases` backs them up on demand.

## 2.1.0

Fewer emails, your choice how many (Settings → Notifications):

* **Email on/off**: one switch stops all email alerts without deleting the address; Telegram and webhooks keep working.
* **Banned-attackers digest**: every hour (as before), every 6 hours, once a day, or never. Bans are always visible in
  Firewall either way.
* **Daily limit** for non-critical alerts (bans, changed files, logins, audit, SSL, new version). The first alert over
  the limit is replaced by a single "daily limit reached" notice. Site down, suspicious code, failed backups and
  restores are always sent.

## 2.0.1

* Fix: the security audit's probes (/.env, /.git, /phpinfo.php …) come from the server's own IP, so the firewall
  counted them as attacks and banned the server — after that every uptime check failed with 403 while the sites
  were fine. HostShield's own requests now carry a secret key (`<data_dir>/waf/internal.key`): the firewall still
  applies its rules to them (the audit sees the real 403), but never counts strikes, bans, rate-limits or logs them
  as attacks. The key is only sent to the protected sites and the dashboard; redirects of those requests are
  followed by hand so it never reaches another host. Not an IP allow-list on purpose: on shared hosting other
  accounts use the same server IP. If the server IP is still banned from before, remove the ban once in Firewall.
* Fix: "Check now" said "Could not reach GitHub" when there was simply no release yet (GitHub answers 404) or when
  update checks were turned off. It now says which one it is.

## 2.0.0 — first public release

* Web installer: finds the sites in the hosting account, detects WordPress, Laravel, Joomla, Drupal, PrestaShop,
  OpenCart and Magento, and reads their database credentials from the application config.
* All settings in the dashboard (no config file editing); English and Bulgarian interface.
* Firewall: one-click exceptions for false positives, per-site rules, WordPress user-enumeration and XML-RPC blocking,
  PHP execution blocked in upload folders, optional Lockdown (only approved scripts run).
* Backups: daily / weekly / monthly retention, S3-compatible off-site storage (AWS, Backblaze B2, Cloudflare R2, Wasabi,
  MinIO) besides FTP, download from off-site storage for disaster recovery.
* Scanner: WordPress core and plugin verification against wordpress.org checksums, uploads scanned, quarantine with undo,
  optional automatic quarantine, "mark as safe".
* Security audit with an A–F grade per site and fixes for every finding.
* Alerts by SMTP, Telegram, Discord, Slack and webhooks; SSL expiry and new-login alerts; hourly ban digest.
* Two-factor login with recovery codes; dashboard IP allow list; session timeout.
* Setup checklist, attack chart, uptime history, update check.

## 1.0.0

* Private version used on the author's own sites: firewall, nightly backups with restore, integrity monitor.
