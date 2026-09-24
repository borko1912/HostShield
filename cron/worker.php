<?php
declare(strict_types=1);

// HostShield worker — the only cron job. Run it every minute:
//   * * * * * /path/to/php /path/to/hostshield/cron/worker.php >/dev/null 2>&1
// The dashboard shows the exact command for your server.
//
// Manual use:
//   php worker.php --backup [site]                 back up now (all sites or one)
//   php worker.php --restore <site> <backup> [all|files|db]
//   php worker.php --scan [site]                   full malware scan with report
//   php worker.php --audit [site]                  security audit with grades
//   php worker.php --uptime                        check that the sites respond
//   php worker.php --status                        backups per site
//   php worker.php --test-notify                   send a test alert to every channel
//   php worker.php --accept <site>                 approve the current files (after a deploy)

if (PHP_SAPI !== 'cli' && !defined('SHIELD_WEB_CRON')) {
    http_response_code(403);
    exit;
}
if (PHP_VERSION_ID < 80100) {
    fwrite(STDERR, 'HostShield needs PHP 8.1+, this cron runs ' . PHP_VERSION . ". Open the dashboard: it shows the exact cron command.\n");
    exit(1);
}

require_once dirname(__DIR__) . '/lib/core.php';
require_once dirname(__DIR__) . '/lib/notify.php';
require_once dirname(__DIR__) . '/lib/backup.php';
require_once dirname(__DIR__) . '/lib/monitor.php';
require_once dirname(__DIR__) . '/lib/audit.php';
require_once dirname(__DIR__) . '/lib/jobs.php';
require_once dirname(__DIR__) . '/lib/updates.php';

@set_time_limit(0);
@ini_set('memory_limit', '1024M');
$cfg = shield_config();
shield_migrate();
$args = defined('SHIELD_WEB_CRON') ? [] : array_slice($argv ?? [], 1);
$cmd = $args[0] ?? '';
$only = $args[1] ?? null;
if ($only !== null && $cmd !== '--restore' && !isset(shield_sites()[$only])) {
    fwrite(STDERR, "Unknown site: {$only}. Sites: " . implode(', ', array_keys(shield_sites())) . "\n");
    exit(1);
}

$eachSite = static function (?string $only, callable $fn): int {
    $errors = 0;
    foreach (array_keys(shield_sites()) as $key) {
        if ($only !== null && $only !== (string)$key) {
            continue;
        }
        try {
            $fn((string)$key);
        } catch (Throwable $e) {
            $errors++;
            shield_log('worker', "{$key}: " . $e->getMessage());
        }
    }
    return $errors;
};

$runBackups = static function (?string $only): void {
    $failed = [];
    $ok = [];
    foreach (shield_sites() as $key => $site) {
        $key = (string)$key;
        if (($only !== null && $only !== $key) || ($only === null && empty($site['backup']))) {
            continue;
        }
        try {
            $m = shield_backup_site($key, $only !== null ? 'manual' : 'daily');
            $ok[$key] = sprintf('%-14s %s  %s  (%d files, %d databases, %s s)%s', $key, $m['name'], shield_human_size((float)$m['total_size']),
                $m['files']['count'], count($m['databases']), $m['duration'], !empty($m['offsite_error']) ? '  OFF-SITE FAILED' : '');
        } catch (Throwable $e) {
            $failed[$key] = $e->getMessage();
        }
    }
    shield_state_update(static function (array $st) use ($ok, $failed): array {
        $st['last_backup_run'] = time();
        $st['last_backup_ok'] = !$failed;
        foreach (array_keys($ok) as $k) {
            unset($st['backup_errors'][$k]);
        }
        foreach ($failed as $k => $msg) {
            $st['backup_errors'][$k] = ['t' => time(), 'msg' => $msg];
        }
        return $st;
    });
    if ($failed) {
        $lines = [];
        foreach ($failed as $k => $msg) {
            $lines[] = $k . ': ' . $msg;
        }
        shield_notify('backup_failed', __('Backup FAILED'), __("Failed:\n%s\n\nSucceeded:\n%s", implode("\n", $lines), implode("\n", $ok) ?: '—'));
    }
};

switch ($cmd) {
    case '--backup':
        $runBackups($only);
        exit(0);
    case '--restore':
        if (count($args) < 3) {
            fwrite(STDERR, "Usage: --restore <site> <backup> [all|files|db]\n");
            exit(1);
        }
        shield_restore($args[1], $args[2], $args[3] ?? 'all', static fn($m) => null);
        exit(0);
    case '--scan':
        $eachSite($only, static function (string $k): void {
            $r = shield_integrity_check($k, false, true);
            echo "{$k}: " . ($r['files_watched'] ?? 0) . ' code files, ' . ($r['uploads_watched'] ?? 0) . ' uploads, new ' . count($r['added'] ?? [])
                . ', modified ' . count($r['modified'] ?? []) . ', deleted ' . count($r['removed'] ?? []) . ', SUSPICIOUS ' . count($r['malware'] ?? []) . "\n";
            foreach ((array)($r['malware'] ?? []) as $f => $x) {
                echo "   ! {$f} [" . implode(', ', $x['rules']) . "] {$x['level']}\n";
            }
            foreach (array_merge((array)($r['wp']['modified'] ?? []), (array)($r['wp']['unknown'] ?? [])) as $f) {
                echo "   ! {$f} [WordPress core mismatch]\n";
            }
        });
        exit(0);
    case '--audit':
        $eachSite($only, static function (string $k): void {
            $r = shield_audit_site($k, false);
            echo "{$k}: grade {$r['grade']} ({$r['score']}/100)\n";
            foreach ($r['checks'] as $c) {
                if ($c['status'] !== 'pass') {
                    echo "   ✗ [{$c['severity']}] {$c['title']}" . ($c['detail'] !== '' ? " — {$c['detail']}" : '') . "\n";
                }
            }
        });
        exit(0);
    case '--accept':
        if ($only === null) {
            fwrite(STDERR, "Usage: --accept <site>\n");
            exit(1);
        }
        $r = shield_integrity_accept($only);
        echo "Approved. Suspicious files still flagged: " . count($r['malware'] ?? []) . "\n";
        exit(0);
    case '--uptime':
        $eachSite(null, static function (string $k): void {
            $s = shield_uptime_check($k);
            echo "{$k}: " . ($s['code'] ?? 0) . ' ' . ($s['ms'] ?? 0) . "ms\n";
        });
        exit(0);
    case '--test-notify':
        $sent = shield_notify('test', __('Test alert'), __('If you can read this, alerts work.'));
        echo $sent ? 'Sent via: ' . implode(', ', $sent) . "\n" : "No channel accepted it. Check Settings → Notifications.\n";
        exit(0);
    case '--status':
        foreach (array_keys(shield_sites()) as $k) {
            $b = shield_list_backups((string)$k);
            echo str_pad((string)$k, 16) . count($b) . ' backups' . ($b ? ', newest ' . $b[0]['name'] : '') . "\n";
        }
        exit(0);
    case '':
        break;
    default:
        fwrite(STDERR, "Unknown option {$cmd}. See the top of this file for usage.\n");
        exit(1);
}

// ---------------- Cron mode (every minute) ----------------
$lock = fopen(shield_dir('') . '/worker.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0); // the previous run is still busy
}
touch(shield_path('worker.lock'));
shield_protect_data_dir();

$now = time();
$state = shield_state_update(static function (array $st) use ($now): array {
    $st['last_worker'] = $now;
    $st['worker_php'] = PHP_VERSION;
    $st['worker_sapi'] = defined('SHIELD_WEB_CRON') ? 'web' : 'cli';
    return $st;
});
$due = static function (string $key, int $every) use (&$state, $now): bool {
    if ($now - (int)($state[$key] ?? 0) < $every - 5) {
        return false;
    }
    $state = shield_state_update(static function (array $st) use ($key, $now): array {
        $st[$key] = $now;
        return $st;
    });
    return true;
};

// 1) Tasks from the dashboard first.
foreach (shield_jobs_pending() as $job) {
    shield_job_run($job);
}

// 2) Firewall bans: one digest per hour.
$alerts = shield_path('waf/alerts.jsonl');
if (is_file($alerts) && filesize($alerts) > 0 && $due('last_ban_digest', 3600)) {
    $proc = $alerts . '.sending';
    @rename($alerts, $proc);
    $lines = array_values(array_filter(array_map(static fn($l) => json_decode($l, true), (array)file($proc, FILE_IGNORE_NEW_LINES))));
    @unlink($proc);
    if ($lines) {
        $body = __('The firewall banned %d IP addresses:', count($lines)) . "\n\n";
        foreach (array_slice($lines, 0, 50) as $a) {
            $body .= date('H:i', (int)$a['t']) . "  {$a['ip']}  {$a['site']}  " . __('for %d min', (int)$a['minutes']) . '  [' . implode(', ', (array)$a['rules']) . "]\n";
        }
        shield_notify('ban', __('Blocked attackers: %d', count($lines)), $body);
    }
}

// 3) Nightly backup.
$hour = (int)($cfg['backup']['hour'] ?? 3);
if (!empty($cfg['backup']['enabled']) && (int)date('G') >= $hour && ($state['last_backup_date'] ?? '') !== date('Y-m-d')) {
    shield_state_update(static function (array $st) use ($now): array {
        $st['last_backup_date'] = date('Y-m-d');
        $st['backup_running'] = $now;
        return $st;
    });
    try {
        $runBackups(null);
    } finally {
        shield_state_update(static function (array $st): array {
            unset($st['backup_running']);
            return $st;
        });
    }
}

// 4) Uptime and SSL.
if ($due('last_uptime', 60 * max(1, (int)($cfg['monitor']['uptime_minutes'] ?? 5)))) {
    $eachSite(null, static fn(string $k) => shield_uptime_check($k));
}

// 5) File integrity and malware.
if ($due('last_integrity', 60 * max(5, (int)($cfg['monitor']['integrity_minutes'] ?? 60)))) {
    $eachSite(null, static fn(string $k) => shield_integrity_check($k));
}

// 6) Security audit.
if ($due('last_audit', 3600 * max(1, (int)($cfg['monitor']['audit_hours'] ?? 24)))) {
    $eachSite(null, static fn(string $k) => shield_audit_site($k));
}

// 7) New HostShield version (once a day).
if ($due('last_update_check', 86400)) {
    $rel = shield_update_available();
    if ($rel && ($state['update_notified'] ?? '') !== $rel['version']) {
        shield_state_update(static function (array $st) use ($rel): array {
            $st['update_notified'] = $rel['version'];
            return $st;
        });
        shield_notify('update', __('HostShield %s is available', $rel['version']), __("You run %s.\nWhat's new and how to update: %s", SHIELD_VERSION, $rel['url']));
    }
}

// 8) Housekeeping (hourly).
if ($due('last_cleanup', 3600)) {
    foreach ((array)glob(shield_path('waf/rate') . '/*') as $f) {
        if ($now - (int)@filemtime((string)$f) > 3600) {
            @unlink((string)$f);
        }
    }
    foreach ((array)glob(shield_path('waf/strikes') . '/*.json') as $f) {
        if ($now - (int)@filemtime((string)$f) > 30 * 86400) {
            @unlink((string)$f);
        }
    }
    foreach ((array)glob(shield_path('waf/bans') . '/*.json') as $f) {
        if ((int)(shield_json_read((string)$f)['until'] ?? 0) < $now) {
            @unlink((string)$f);
        }
    }
    foreach (array_merge((array)glob(shield_path('logs') . '/*'), (array)glob(shield_path('jobs') . '/*.json'), (array)glob(shield_path('auth') . '/*.json')) as $f) {
        if ($now - (int)@filemtime((string)$f) > 30 * 86400) {
            @unlink((string)$f);
        }
    }
    foreach ((array)glob(shield_path('staging') . '/*') as $f) {
        if ($now - (int)@filemtime((string)$f) > 86400) {
            shield_rrmdir((string)$f);
        }
    }
    foreach ((array)glob(shield_path('quarantine') . '/*/*', GLOB_ONLYDIR) as $f) {
        if ($now - (int)@filemtime((string)$f) > 90 * 86400) {
            shield_rrmdir((string)$f);
        }
    }
}

flock($lock, LOCK_UN);
fclose($lock);
