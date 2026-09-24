<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';
require_once __DIR__ . '/notify.php';
require_once __DIR__ . '/backup.php';
require_once __DIR__ . '/monitor.php';

// Security audit: checks a site from the outside (HTTP) and the inside (files, settings),
// then grades it A–F. Each failed check says how to fix it.

const SHIELD_SEVERITY_POINTS = ['critical' => 35, 'high' => 15, 'medium' => 7, 'low' => 3, 'info' => 0];

function shield_grade(int $score): string
{
    return match (true) {
        $score >= 90 => 'A',
        $score >= 80 => 'B',
        $score >= 70 => 'C',
        $score >= 55 => 'D',
        default => 'F',
    };
}

function shield_audit_result(string $siteKey): array
{
    return shield_json_read(shield_path('audit/' . $siteKey . '.json'));
}

function shield_audit_site(string $siteKey, bool $notify = true): array
{
    $site = shield_site($siteKey);
    $checks = [];
    $add = static function (string $id, string $severity, bool $ok, string $title, string $detail = '', string $fix = '', bool $warnOnly = false) use (&$checks): void {
        $checks[] = ['id' => $id, 'severity' => $severity, 'status' => $ok ? 'pass' : ($warnOnly ? 'warn' : 'fail'),
            'title' => $title, 'detail' => $detail, 'fix' => $ok ? '' : $fix];
    };
    $url = rtrim((string)$site['url'], '/');
    $home = null;

    if ($url !== '') {
        $home = shield_http($url . '/', ['range' => '0-65535', 'timeout' => 20]);
        $host = (string)parse_url($url, PHP_URL_HOST);
        $https = str_starts_with($url, 'https://');
        $add('https', 'high', $https && $home['code'] > 0 && $home['error'] === '',
            __('HTTPS'), $https ? ($home['error'] ?: '') : __('The site URL is not HTTPS.'),
            __('Enable a free SSL certificate (AutoSSL / Let\'s Encrypt) in your hosting panel and use https:// in the site URL.'));
        if ($https) {
            $plain = shield_http('http://' . $host . '/', ['follow' => false, 'timeout' => 15, 'nobody' => true]);
            $loc = (string)($plain['headers']['location'] ?? '');
            $add('https_redirect', 'medium', in_array($plain['code'], [301, 302, 307, 308], true) && str_starts_with($loc, 'https://'),
                __('HTTP redirects to HTTPS'), $plain['code'] ? 'HTTP ' . $plain['code'] : $plain['error'],
                __('Redirect all http:// traffic to https:// (hosting panel "Force HTTPS", or a rewrite rule in .htaccess).'));
            $ssl = shield_ssl_days_left($host, (int)(parse_url($url, PHP_URL_PORT) ?: 443));
            if ($ssl) {
                $add('ssl_expiry', $ssl['days'] < 7 ? 'high' : 'medium', $ssl['days'] >= (int)(shield_config()['monitor']['ssl_warn_days'] ?? 14),
                    __('SSL certificate validity'), __('%d days left (%s, until %s)', $ssl['days'], $ssl['issuer'], date('Y-m-d', $ssl['expires'])),
                    __('Renew the certificate in your hosting panel. Let\'s Encrypt certificates renew automatically when AutoSSL is on.'));
            }
        }
        $h = (array)$home['headers'];
        $add('hsts', 'low', isset($h['strict-transport-security']), __('HSTS header'), '',
            __('Add the header Strict-Transport-Security: max-age=31536000 (in .htaccess: Header always set Strict-Transport-Security "max-age=31536000").'));
        $add('nosniff', 'low', strtolower((string)($h['x-content-type-options'] ?? '')) === 'nosniff', __('X-Content-Type-Options header'), '',
            __('Add the header X-Content-Type-Options: nosniff.'));
        $add('frame', 'low', isset($h['x-frame-options']) || str_contains(strtolower((string)($h['content-security-policy'] ?? '')), 'frame-ancestors'),
            __('Clickjacking protection'), '', __('Add the header X-Frame-Options: SAMEORIGIN.'));
        $powered = (string)($h['x-powered-by'] ?? '');
        $add('powered_by', 'low', !preg_match('/php\/\d/i', $powered), __('PHP version hidden'), $powered,
            __('Set expose_php = Off in the PHP settings of your hosting panel.'));

        // Files that must never be downloadable.
        $probes = [
            '/.env' => ['critical', static fn($b) => (bool)preg_match('/^\s*[A-Z_]+\s*=/m', $b)],
            '/.git/HEAD' => ['high', static fn($b) => str_starts_with(ltrim($b), 'ref:')],
            '/.git/config' => ['high', static fn($b) => str_contains($b, '[core]')],
            '/wp-config.php.bak' => ['critical', static fn($b) => str_contains($b, 'DB_PASSWORD')],
            '/wp-config.php~' => ['critical', static fn($b) => str_contains($b, 'DB_PASSWORD')],
            '/wp-config.php.save' => ['critical', static fn($b) => str_contains($b, 'DB_PASSWORD')],
            '/config.php.bak' => ['critical', static fn($b) => str_contains($b, '<?php')],
            '/backup.zip' => ['high', static fn($b) => str_starts_with($b, 'PK')],
            '/backup.sql' => ['critical', static fn($b) => (bool)preg_match('/CREATE TABLE|INSERT INTO/i', $b)],
            '/dump.sql' => ['critical', static fn($b) => (bool)preg_match('/CREATE TABLE|INSERT INTO/i', $b)],
            '/database.sql' => ['critical', static fn($b) => (bool)preg_match('/CREATE TABLE|INSERT INTO/i', $b)],
            '/phpinfo.php' => ['medium', static fn($b) => str_contains($b, 'PHP Version')],
            '/info.php' => ['medium', static fn($b) => str_contains($b, 'PHP Version')],
            '/error_log' => ['medium', static fn($b) => (bool)preg_match('/PHP (Warning|Fatal|Notice|Deprecated)/', $b)],
            '/wp-content/debug.log' => ['medium', static fn($b) => (bool)preg_match('/PHP (Warning|Fatal|Notice|Deprecated)/', $b)],
            '/.htpasswd' => ['high', static fn($b) => (bool)preg_match('/^[^:\s]+:\$?[a-z0-9.\/$]+/im', $b)],
        ];
        $exposed = [];
        $worst = 'info';
        foreach ($probes as $path => [$sev, $test]) {
            $r = shield_http($url . $path, ['follow' => false, 'range' => '0-2047', 'timeout' => 10]);
            if (($r['code'] === 200 || $r['code'] === 206) && $test($r['body'])) {
                $exposed[] = $path;
                if (SHIELD_SEVERITY_POINTS[$sev] > SHIELD_SEVERITY_POINTS[$worst]) {
                    $worst = $sev;
                }
            }
        }
        $add('exposed_files', $exposed ? $worst : 'high', !$exposed, __('Sensitive files not downloadable'), implode(', ', $exposed),
            __('Delete these files from the web folder (or block them in .htaccess). They can leak passwords and data.'));

        $listDir = '';
        foreach ((array)$site['upload_dirs'] as $u) {
            $r = shield_http($url . '/' . trim((string)$u, '/') . '/', ['follow' => false, 'range' => '0-4095', 'timeout' => 10]);
            if (($r['code'] === 200 || $r['code'] === 206) && preg_match('/<title>\s*Index of \//i', $r['body'])) {
                $listDir = '/' . trim((string)$u, '/') . '/';
                break;
            }
        }
        $add('dir_listing', 'medium', $listDir === '', __('Directory listing disabled'), $listDir,
            __('Add "Options -Indexes" to the site\'s .htaccess so visitors cannot list folder contents.'));
    }

    // Inside checks.
    $hb = shield_path('waf/heartbeat/' . $siteKey);
    $wafOn = is_file($hb) && time() - (int)filemtime($hb) < 86400 * 2;
    $add('firewall', 'high', $wafOn, __('Firewall active'), $wafOn ? '' : __('No requests passed through the firewall in the last 2 days.'),
        __('Open the site in HostShield and click “Enable firewall”.'));
    $mode = (string)(($site['waf_mode'] ?? null) ?: (shield_config()['waf']['mode'] ?? 'log'));
    if ($wafOn) {
        $add('firewall_block', 'medium', $mode === 'block', __('Firewall blocks attacks'), __('Mode: %s', $mode),
            __('After a few days in log mode without false positives, switch the firewall to Block.'), true);
    }

    if (!empty($site['backup'])) {
        $list = shield_list_backups($siteKey);
        $last = $list[0]['created'] ?? 0;
        $add('backup_recent', 'high', $last > time() - 2 * 86400, __('Recent backup'), $last ? shield_ago((int)$last) : __('none'),
            __('Check that the cron job runs; the dashboard home page shows the exact command.'));
        $add('backup_offsite', 'medium', shield_offsite_enabled(), __('Off-site backup copy'), '',
            __('Backups on the same server are lost if the server is. Add S3/B2/R2 or FTP storage in Settings → Backups.'));
    }

    $rep = shield_integrity_report($siteKey);
    $mal = count((array)($rep['malware'] ?? []));
    $add('malware', 'critical', $mal === 0, __('No suspicious code'), $mal ? __('%d suspicious files', $mal) : '',
        __('Review the flagged files on the Files tab: quarantine them, or restore the site from a clean backup.'));

    // World-writable code files.
    $baseline = shield_json_read(shield_path('integrity/' . $siteKey . '.baseline.json'));
    $writable = [];
    foreach (array_slice(array_keys((array)($baseline['files'] ?? [])), 0, 20000) as $rel) {
        $p = @fileperms($site['path'] . '/' . $rel);
        if ($p !== false && ($p & 0x0002)) {
            $writable[] = $rel;
        }
    }
    $add('permissions', 'medium', !$writable, __('No world-writable code files'), implode(', ', array_slice($writable, 0, 5)) . (count($writable) > 5 ? ' …' : ''),
        __('Set files to 644 and folders to 755 (hosting File Manager → Permissions).'));

    if (($site['platform'] ?? '') === 'wordpress') {
        require_once __DIR__ . '/wordpress.php';
        $wpv = shield_wp_version($site['path']);
        $latest = shield_wp_latest();
        if ($wpv['version'] !== '' && $latest !== '') {
            $major = static fn(string $v): string => implode('.', array_slice(explode('.', $v), 0, 2));
            $behindMajor = version_compare($major($wpv['version']), $major($latest), '<');
            $add('wp_version', $behindMajor ? 'high' : 'medium', version_compare($wpv['version'], $latest, '>='),
                __('WordPress up to date'), __('Installed %s, latest %s', $wpv['version'], $latest), __('Update WordPress from Dashboard → Updates (take a backup first).'));
        }
        $wp = (array)($rep['wp'] ?? []);
        $core = array_merge((array)($wp['modified'] ?? []), (array)($wp['unknown'] ?? []));
        $add('wp_core', 'critical', !$core, __('WordPress core files match wordpress.org'), implode(', ', array_slice($core, 0, 5)) . (count($core) > 5 ? ' …' : ''),
            __('Reinstall WordPress core (Dashboard → Updates → Re-install) and remove unknown files from wp-admin and wp-includes.'));
        $plugChanged = array_keys(array_filter((array)($wp['plugins'] ?? []), static fn($p) => ($p['status'] ?? '') === 'changed'));
        $add('wp_plugins', 'high', !$plugChanged, __('Plugins match wordpress.org'), implode(', ', $plugChanged),
            __('Reinstall the listed plugins from wordpress.org (delete and install again).'));
        $flags = shield_wp_config_flags($site['path']);
        $add('wp_debug', 'medium', !$flags['debug'] || $flags['debug_display'] === false, __('WP_DEBUG output off'), '',
            __('In wp-config.php set WP_DEBUG to false on a live site.'));
        $add('wp_file_edit', 'low', $flags['file_edit_disabled'], __('Theme/plugin editor disabled'), '',
            __("Add define('DISALLOW_FILE_EDIT', true); to wp-config.php so a stolen admin login cannot edit PHP code."));
        $add('wp_salts', 'high', !$flags['salts_default'], __('Unique security keys (salts)'), '',
            __('Generate new keys at https://api.wordpress.org/secret-key/1.1/salt/ and paste them into wp-config.php.'));
        if ($url !== '') {
            $readme = shield_http($url . '/readme.html', ['follow' => false, 'range' => '0-2047', 'timeout' => 10]);
            $add('wp_readme', 'low', !(($readme['code'] === 200 || $readme['code'] === 206) && stripos($readme['body'], 'wordpress') !== false),
                __('readme.html removed'), '', __('Delete readme.html from the site root: it reveals the WordPress version.'));
            $enum = shield_http($url . '/?author=1', ['follow' => false, 'timeout' => 10, 'nobody' => true]);
            $add('wp_user_enum', 'low', !(in_array($enum['code'], [301, 302], true) && str_contains((string)($enum['headers']['location'] ?? ''), '/author/')),
                __('Usernames hidden'), '', __('Turn on “Block WordPress user enumeration” in the firewall settings.'));
        }
    }

    $points = 0;
    foreach ($checks as $c) {
        if ($c['status'] === 'fail') {
            $points += SHIELD_SEVERITY_POINTS[$c['severity']];
        } elseif ($c['status'] === 'warn') {
            $points += intdiv(SHIELD_SEVERITY_POINTS[$c['severity']], 2);
        }
    }
    $score = max(0, 100 - $points);
    $result = ['checked' => time(), 'score' => $score, 'grade' => shield_grade($score), 'checks' => $checks];

    $prev = shield_audit_result($siteKey);
    $prevFailed = [];
    foreach ((array)($prev['checks'] ?? []) as $c) {
        if ($c['status'] === 'fail') {
            $prevFailed[$c['id']] = true;
        }
    }
    $newBad = array_filter($checks, static fn($c) => $c['status'] === 'fail' && in_array($c['severity'], ['critical', 'high'], true) && !isset($prevFailed[$c['id']]));
    if ($notify && $prev && $newBad) {
        $body = __('Site: %s — grade %s (%d/100)', $site['title'], $result['grade'], $score) . "\n\n";
        foreach ($newBad as $c) {
            $body .= '✗ ' . $c['title'] . ($c['detail'] !== '' ? ': ' . $c['detail'] : '') . "\n  → " . $c['fix'] . "\n\n";
        }
        shield_notify('audit', __('New security problems: %s', $site['title']), $body);
    }
    shield_json_write(shield_path('audit/' . $siteKey . '.json'), $result);
    return $result;
}

/** Account-wide grade: the average site score, capped by the worst site plus 15. */
function shield_overall_score(): ?array
{
    $scores = [];
    foreach (array_keys(shield_sites()) as $k) {
        $a = shield_audit_result((string)$k);
        if (isset($a['score'])) {
            $scores[] = (int)$a['score'];
        }
    }
    if (!$scores) {
        return null;
    }
    $score = (int)min(round(array_sum($scores) / count($scores)), min($scores) + 15);
    return ['score' => $score, 'grade' => shield_grade($score)];
}
