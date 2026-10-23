# CLAUDE.md — HostShield

Public (open source) firewall, backup, and malware scanner for shared hosting accounts (cPanel, SPanel, Plesk, DirectAdmin). No root, no Docker. Protects every site in a hosting account from a single installation.

## Stack
- PHP (no framework, no Composer in production), MariaDB/MySQL optional
- Supports: WordPress, Laravel, Joomla, Drupal, PrestaShop, OpenCart, plain PHP
- CI: GitHub Actions + E2E tests (`tests/`)
- Public repo: github.com/borko1912/HostShield

## Key features
- **WAF** (`waf/firewall.php`) — runs before every PHP request via `auto_prepend_file`. Log-only mode first, then blocking.
- **Web shell blocking** — PHP never executes from upload dirs; optional Lockdown mode
- **Backups** — files + DB nightly, S3/Backblaze B2/Cloudflare R2/Wasabi/MinIO/FTP, one-click restore
- **Scanner** — file monitor, known shell signatures, WordPress core/plugin checksum verification
- **Security audit** — 20+ checks per site, A–F score
- **Notifications** — email (PHP mail or SMTP), Telegram, Discord, Slack, webhook

## Folder structure
| Folder | Purpose |
|---|---|
| `app/` | Dashboard application |
| `lib/` | Core libraries |
| `waf/` | WAF/firewall logic |
| `cron/` | Cron job scripts |
| `lang/` | Translations (bg, en) |
| `assets/` | CSS, JS, images |
| `docs/` | Documentation |
| `tests/` | E2E and unit tests |

## Important rules
- `config.php` (copied from `config.sample.php`) is NOT in git — contains admin credentials and paths.
- WAF is activated per site via `auto_prepend_file` in the site's `php.ini`.
- Data dir (backups, logs, settings) lives OUTSIDE web root — configure `data_dir` in config.
- Start WAF in log-only mode, review false positives, then enable blocking.
- This is the PUBLIC platform. `shield-worxloc-com` is the private deployment that overlays this repo for the `ritonbgc` hosting account.
- All PRs must pass CI + E2E before merging.
- Donations / paid work accepted — see README.
