<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';
require_once __DIR__ . '/notify.php';
require_once __DIR__ . '/scanner.php';

/**
 * Snapshot of a site's files.
 *  code:    rel => [sha1, size] for code and server config (changes need approval)
 *  uploads: rel => "mtime:size" for everything in upload folders (scanned, never reported as changes)
 */
function shield_snapshot(array $site): array
{
    $code = [];
    $uploads = [];
    foreach (shield_walk($site) as $rel => $f) {
        if ($f->isDir()) {
            continue;
        }
        $ext = strtolower($f->getExtension());
        $base = strtolower($f->getFilename());
        $upl = shield_in_uploads($rel, $site);
        $watch = in_array($ext, SHIELD_WATCH_EXT, true) || $base === '.htaccess' || $base === '.user.ini';
        if ($watch && (!$upl || in_array($ext, SHIELD_CODE_EXT, true) || $base === '.htaccess' || $base === '.user.ini')) {
            $code[$rel] = [(string)@sha1_file($f->getPathname()), (int)$f->getSize()];
        } elseif ($upl) {
            $uploads[$rel] = $f->getMTime() . ':' . $f->getSize();
        }
    }
    return ['code' => $code, 'uploads' => $uploads];
}

/** Approved scripts for Lockdown mode: data/waf/exec-<site>.php (rel => 1). */
function shield_write_exec_allowlist(string $siteKey, array $code): void
{
    $allow = [];
    foreach (array_keys($code) as $rel) {
        if (in_array(strtolower(pathinfo($rel, PATHINFO_EXTENSION)), SHIELD_CODE_EXT, true)) {
            $allow[$rel] = 1;
        }
    }
    shield_php_write(shield_dir('waf') . '/exec-' . $siteKey . '.php', $allow, 'Scripts allowed to run in Lockdown mode');
}

function shield_integrity_report(string $siteKey): array
{
    return shield_json_read(shield_path('integrity/' . $siteKey . '.report.json'),
        ['added' => [], 'modified' => [], 'removed' => [], 'malware' => [], 'notified_hash' => '']);
}

/**
 * Integrity check of one site.
 * The first run records a baseline and scans every file.
 */
function shield_integrity_check(string $siteKey, bool $notify = true, bool $fullScan = false): array
{
    $site = shield_site($siteKey);
    if (!is_dir($site['path'])) {
        return ['error' => __('Folder does not exist')];
    }
    $baseFile = shield_path('integrity/' . $siteKey . '.baseline.json');
    $repFile = shield_path('integrity/' . $siteKey . '.report.json');
    $snap = shield_snapshot($site);
    $baseline = shield_json_read($baseFile);
    $report = shield_integrity_report($siteKey);
    foreach (['added', 'modified', 'removed', 'malware'] as $k) {
        $report[$k] = (array)($report[$k] ?? []);
    }

    $first = !$baseline;
    $toScan = [];
    if ($first || $fullScan) {
        $toScan = array_merge(array_keys($snap['code']), array_keys($snap['uploads']));
    }
    if (!$first) {
        foreach ($snap['code'] as $rel => [$hash]) {
            if (!isset($baseline['files'][$rel])) {
                $report['added'][$rel] ??= time();
                $toScan[] = $rel;
            } elseif ($baseline['files'][$rel][0] !== $hash) {
                $report['modified'][$rel] ??= time();
                $toScan[] = $rel;
            } else {
                unset($report['added'][$rel], $report['modified'][$rel]);
            }
        }
        foreach ((array)$baseline['files'] as $rel => $_) {
            if (!isset($snap['code'][$rel])) {
                $report['removed'][$rel] ??= time();
            } else {
                unset($report['removed'][$rel]);
            }
        }
        foreach (array_keys($report['added'] + $report['modified']) as $rel) {
            if (!isset($snap['code'][$rel])) {
                unset($report['added'][$rel], $report['modified'][$rel]);
            }
        }
        foreach ($snap['uploads'] as $rel => $sig) {
            if (($baseline['uploads'][$rel] ?? null) !== $sig) {
                $toScan[] = $rel;
            }
        }
    }

    // A flagged file that changed since is scanned again.
    foreach ($report['malware'] as $rel => $x) {
        $cur = $snap['code'][$rel][0] ?? (isset($snap['uploads'][$rel]) ? (string)@sha1_file($site['path'] . '/' . $rel) : null);
        if ($cur !== null && ($x['hash'] ?? '') !== $cur) {
            $toScan[] = $rel;
        }
    }
    $ignore = (array)($site['scan_ignore'] ?? []);
    $newMalware = [];
    foreach (array_unique($toScan) as $rel) {
        $file = $site['path'] . '/' . $rel;
        $hash = $snap['code'][$rel][0] ?? (string)@sha1_file($file);
        if (isset($ignore[$rel]) && $ignore[$rel] === $hash) {
            unset($report['malware'][$rel]);
            continue;
        }
        $hit = shield_scan_file($file, shield_in_uploads($rel, $site));
        if ($hit) {
            $isNew = !isset($report['malware'][$rel]);
            $report['malware'][$rel] = ['rules' => $hit['rules'], 'level' => $hit['level'], 't' => time(), 'hash' => $hash];
            if ($isNew) {
                $newMalware[$rel] = $hit;
            }
        } else {
            unset($report['malware'][$rel]);
        }
    }
    foreach (array_keys($report['malware']) as $rel) {
        if (!isset($snap['code'][$rel]) && !isset($snap['uploads'][$rel])) {
            unset($report['malware'][$rel]);
        }
    }

    // Auto-quarantine: only high-confidence findings.
    $quarantined = [];
    if (!empty(shield_config()['monitor']['auto_quarantine'])) {
        foreach ($newMalware as $rel => $hit) {
            if ($hit['level'] === 'high') {
                try {
                    shield_quarantine_file($siteKey, $rel, $hit['rules']);
                    unset($report['malware'][$rel], $report['added'][$rel], $report['modified'][$rel]);
                    $quarantined[$rel] = $hit['rules'];
                } catch (Throwable $e) {
                    shield_log('quarantine', 'ERROR ' . $e->getMessage());
                }
            }
        }
    }

    // WordPress: verify core and plugins daily, or when core folders changed.
    if (($site['platform'] ?? '') === 'wordpress') {
        $coreChanged = false;
        foreach (array_keys($report['added'] + $report['modified']) as $rel) {
            if (str_starts_with($rel, 'wp-admin/') || str_starts_with($rel, 'wp-includes/') || str_starts_with($rel, 'wp-content/plugins/')) {
                $coreChanged = true;
                break;
            }
        }
        if ($coreChanged || $fullScan || time() - (int)($report['wp']['checked'] ?? 0) > 86400) {
            require_once __DIR__ . '/wordpress.php';
            try {
                $report['wp'] = shield_wp_verify($site);
            } catch (Throwable $e) {
                $report['wp'] = ['checked' => time(), 'error' => $e->getMessage()];
            }
        }
    }

    $baselineChanged = false;
    if ($first) {
        $baseline = ['created' => time(), 'files' => $snap['code'], 'uploads' => $snap['uploads']];
        $baselineChanged = true;
        shield_write_exec_allowlist($siteKey, $snap['code']);
    } elseif (($baseline['uploads'] ?? []) !== $snap['uploads']) {
        $baseline['uploads'] = $snap['uploads'];
        $baselineChanged = true;
    }
    if ($quarantined) {
        foreach (array_keys($quarantined) as $rel) {
            unset($baseline['files'][$rel], $baseline['uploads'][$rel]);
        }
        $baselineChanged = true;
    }
    if ($baselineChanged) {
        shield_json_write($baseFile, $baseline);
    }
    $report['checked'] = time();
    $report['files_watched'] = count($snap['code']);
    $report['uploads_watched'] = count($snap['uploads']);

    $wpBad = array_merge((array)($report['wp']['modified'] ?? []), (array)($report['wp']['unknown'] ?? []));
    $sig = sha1(json_encode([array_keys($report['added']), array_keys($report['modified']), array_keys($report['removed']), array_keys($report['malware']), $wpBad, array_keys($quarantined)]));
    $hasIssues = $report['added'] || $report['modified'] || $report['removed'] || $report['malware'] || $wpBad || $quarantined;
    if ($notify && $hasIssues && $sig !== ($report['notified_hash'] ?? '')) {
        $body = __('Site: %s', $site['title']) . "\n\n";
        $sections = [
            'malware' => __('⚠ SUSPICIOUS CODE'),
            'added' => __('New files'),
            'modified' => __('Modified files'),
            'removed' => __('Deleted files'),
        ];
        if ($quarantined) {
            $body .= __('Moved to quarantine automatically (%d):', count($quarantined)) . "\n";
            foreach ($quarantined as $rel => $rules) {
                $body .= '  - ' . $rel . '  [' . implode(', ', $rules) . "]\n";
            }
            $body .= "\n";
        }
        if ($wpBad) {
            $body .= __('WordPress core files that differ from wordpress.org (%d):', count($wpBad)) . "\n";
            foreach (array_slice($wpBad, 0, 30) as $rel) {
                $body .= '  - ' . $rel . "\n";
            }
            $body .= "\n";
        }
        foreach ($sections as $k => $label) {
            if ($report[$k]) {
                $body .= $label . ' (' . count($report[$k]) . "):\n";
                foreach (array_slice(array_keys($report[$k]), 0, 40) as $rel) {
                    $body .= '  - ' . $rel . ($k === 'malware' ? '  [' . implode(', ', $report['malware'][$rel]['rules']) . ']' : '') . "\n";
                }
                $body .= "\n";
            }
        }
        $body .= __("If you made these changes (deploy, update), click “Approve changes” in the dashboard.\nIf not, the site may be hacked: restore it from a backup.");
        $danger = $report['malware'] || $wpBad || $quarantined;
        shield_notify($danger ? 'malware' : 'changes', ($danger ? __('SUSPICIOUS CODE: %s', $site['title']) : __('Files changed: %s', $site['title'])), $body);
        $report['notified_hash'] = $sig;
    }
    shield_json_write($repFile, $report);
    return $report;
}

/** Approves the current state (after your own deploy or update) and rescans everything. */
function shield_integrity_accept(string $siteKey): array
{
    $site = shield_site($siteKey);
    $snap = shield_snapshot($site);
    shield_json_write(shield_path('integrity/' . $siteKey . '.baseline.json'), ['created' => time(), 'files' => $snap['code'], 'uploads' => $snap['uploads']]);
    shield_write_exec_allowlist($siteKey, $snap['code']);
    $rep = shield_integrity_report($siteKey);
    shield_json_write(shield_path('integrity/' . $siteKey . '.report.json'), [
        'added' => [], 'modified' => [], 'removed' => [], 'malware' => [],
        'wp' => $rep['wp'] ?? [], 'notified_hash' => '', 'accepted' => time(),
    ]);
    shield_log('integrity', 'Approved changes for ' . $siteKey);
    // Suspicious code stays flagged until the file is fixed, removed or ignored.
    return shield_integrity_check($siteKey, false, true);
}

/** Marks a flagged file as safe (as long as its content does not change). */
function shield_scan_ignore(string $siteKey, string $rel): void
{
    $site = shield_site($siteKey);
    $file = $site['path'] . '/' . ltrim($rel, '/');
    if (!is_file($file)) {
        throw new RuntimeException(__('File not found: %s', $rel));
    }
    $s = shield_settings();
    $s['sites'][$siteKey]['scan_ignore'][$rel] = (string)sha1_file($file);
    shield_settings_save($s);
    $rf = shield_path('integrity/' . $siteKey . '.report.json');
    $rep = shield_json_read($rf);
    unset($rep['malware'][$rel]);
    shield_json_write($rf, $rep);
}

// ------------------------------------------------------------------ uptime and SSL

function shield_uptime_check(string $siteKey): array
{
    $site = shield_site($siteKey);
    $file = shield_path('uptime/' . $siteKey . '.json');
    $st = shield_json_read($file, ['fails' => 0, 'last_ok' => 0, 'down_since' => 0, 'history' => []]);
    $url = (string)($site['url'] ?? '');
    if ($url === '') {
        return $st;
    }
    $r = shield_http($url, ['range' => '0-4096', 'timeout' => 20, 'ua' => 'HostShieldMonitor/' . SHIELD_VERSION]);
    $ok = $r['code'] >= 200 && $r['code'] < 400;
    $st['code'] = $r['code'];
    $st['ms'] = $r['ms'];
    $st['error'] = $r['error'];
    $st['checked'] = time();
    $st['history'] = array_slice(array_merge((array)$st['history'], [[time(), $ok ? 1 : 0, $r['ms']]]), -2016); // 7 days at 5 min
    if ($ok) {
        if ((int)$st['fails'] >= 2) {
            $mins = (int)round((time() - (int)$st['down_since']) / 60);
            shield_notify('down', __('Site is back up: %s', $site['title']), __('%s responds with %d again. It was down for about %d min.', $url, $r['code'], $mins));
        }
        $st['fails'] = 0;
        $st['down_since'] = 0;
        $st['last_ok'] = time();
    } else {
        $st['fails'] = (int)$st['fails'] + 1;
        if ($st['fails'] === 1) {
            $st['down_since'] = time();
        }
        if ($st['fails'] === 2) {
            shield_notify('down', __('SITE DOWN: %s', $site['title']), __("%s\nCode: %d\nError: %s\n\nIf it was hacked or a deploy broke it, restore it from the dashboard.", $url, $r['code'], $r['error']));
        }
    }

    // TLS certificate, twice a day.
    if (str_starts_with($url, 'https://') && time() - (int)($st['ssl']['checked'] ?? 0) > 43200) {
        $host = (string)parse_url($url, PHP_URL_HOST);
        $ssl = shield_ssl_days_left($host, (int)(parse_url($url, PHP_URL_PORT) ?: 443));
        $st['ssl'] = ($ssl ?? ['days' => null]) + ['checked' => time()];
        $warn = (int)(shield_config()['monitor']['ssl_warn_days'] ?? 14);
        if ($ssl && $ssl['days'] <= $warn && ($st['ssl_notified'] ?? '') !== date('Y-m-d')) {
            $st['ssl_notified'] = date('Y-m-d');
            shield_notify('ssl', __('SSL certificate expires in %d days: %s', $ssl['days'], $host),
                __("The certificate of %s expires on %s (issuer: %s).\nRenew it in your hosting panel (AutoSSL / Let's Encrypt).", $host, date('Y-m-d', $ssl['expires']), $ssl['issuer']));
        }
    }
    shield_json_write($file, $st);
    return $st;
}

/** Uptime percentage over the stored history (null when no data). */
function shield_uptime_percent(array $st, int $seconds = 86400): ?float
{
    $from = time() - $seconds;
    $rows = array_filter((array)($st['history'] ?? []), static fn($h) => (int)$h[0] >= $from);
    if (!$rows) {
        return null;
    }
    return round(100 * array_sum(array_column($rows, 1)) / count($rows), 2);
}
