# Changelog

## Unreleased

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
