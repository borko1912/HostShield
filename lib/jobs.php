<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

// Heavy work (backups, restores, scans) goes through a queue that cron/worker.php runs,
// so it never depends on the time limit of a web request.

const SHIELD_JOB_TYPES = ['backup', 'restore', 'integrity', 'audit', 'offsite_fetch'];

function shield_job_add(string $type, array $params, string $by = 'system'): string
{
    $id = date('YmdHis') . '-' . bin2hex(random_bytes(3));
    shield_json_write(shield_dir('jobs') . '/' . $id . '.json', [
        'id' => $id, 'type' => $type, 'params' => $params, 'status' => 'queued',
        'created' => time(), 'by' => $by, 'log' => [],
    ]);
    return $id;
}

function shield_job_get(string $id): array
{
    if (!preg_match('/^[0-9]{14}-[0-9a-f]{6}$/', $id)) {
        return [];
    }
    return shield_json_read(shield_path('jobs/' . $id . '.json'));
}

function shield_job_save(array $job): void
{
    shield_json_write(shield_path('jobs/' . $job['id'] . '.json'), $job);
}

function shield_jobs(int $limit = 50): array
{
    $files = (array)glob(shield_path('jobs') . '/*.json');
    rsort($files);
    $out = [];
    foreach (array_slice($files, 0, $limit) as $f) {
        $j = shield_json_read((string)$f);
        if ($j) {
            $out[] = $j;
        }
    }
    return $out;
}

function shield_jobs_pending(): array
{
    $files = (array)glob(shield_path('jobs') . '/*.json');
    sort($files);
    $out = [];
    foreach ($files as $f) {
        $j = shield_json_read((string)$f);
        if (($j['status'] ?? '') === 'queued') {
            $out[] = $j;
        }
    }
    return $out;
}

function shield_job_active(string $type, string $site): bool
{
    foreach (shield_jobs(100) as $j) {
        if ($j['type'] === $type && ($j['params']['site'] ?? '') === $site && in_array($j['status'], ['queued', 'running'], true)) {
            return true;
        }
    }
    return false;
}

function shield_job_label(string $type): string
{
    return match ($type) {
        'backup' => __('Backup'),
        'restore' => __('Restore'),
        'integrity' => __('File scan'),
        'audit' => __('Security audit'),
        'offsite_fetch' => __('Download from off-site'),
        default => $type,
    };
}

function shield_job_run(array $job): array
{
    require_once __DIR__ . '/backup.php';
    require_once __DIR__ . '/monitor.php';
    require_once __DIR__ . '/audit.php';

    $job['status'] = 'running';
    $job['started'] = time();
    shield_job_save($job);
    $say = static function (string $m) use (&$job): void {
        $job['log'][] = [time(), $m];
        shield_job_save($job);
    };
    $site = (string)($job['params']['site'] ?? '');
    try {
        switch ($job['type']) {
            case 'backup':
                try {
                    $m = shield_backup_site($site, 'manual', $say);
                } catch (Throwable $e) {
                    shield_state_update(static function (array $st) use ($site, $e): array {
                        $st['backup_errors'][$site] = ['t' => time(), 'msg' => $e->getMessage()];
                        return $st;
                    });
                    throw $e;
                }
                shield_state_update(static function (array $st) use ($site): array {
                    unset($st['backup_errors'][$site]);
                    return $st;
                });
                $say(__('Backup %s — %s', $m['name'], shield_human_size((float)$m['total_size'])) . (!empty($m['offsite']) ? ' · ' . __('copied off-site') : ''));
                if (!empty($m['offsite_error'])) {
                    $say(__('Off-site copy failed: %s', $m['offsite_error']));
                }
                break;
            case 'restore':
                $job['result'] = shield_restore($site, (string)$job['params']['backup'], (string)($job['params']['scope'] ?? 'all'), $say);
                break;
            case 'integrity':
                $r = shield_integrity_check($site, true, true);
                $say(__('%d files checked, %d suspicious', (int)($r['files_watched'] ?? 0) + (int)($r['uploads_watched'] ?? 0), count((array)($r['malware'] ?? []))));
                break;
            case 'audit':
                $r = shield_audit_site($site);
                $say(__('Grade %s (%d/100)', $r['grade'], $r['score']));
                break;
            case 'offsite_fetch':
                shield_offsite_fetch($site, (string)$job['params']['backup'], $say);
                $say(__('Downloaded. You can restore it from the Backups tab now.'));
                break;
            default:
                throw new RuntimeException('Unknown job ' . $job['type']);
        }
        $job['status'] = 'done';
    } catch (Throwable $e) {
        $job['status'] = 'error';
        $job['error'] = $e->getMessage();
        $job['log'][] = [time(), __('ERROR: %s', $e->getMessage())];
        shield_log('job', $job['id'] . ' ' . $job['type'] . ' ERROR: ' . $e->getMessage());
        require_once __DIR__ . '/notify.php';
        shield_notify($job['type'] === 'backup' ? 'backup_failed' : 'restore', __('Task failed: %s %s', shield_job_label($job['type']), $site), $e->getMessage());
    }
    $job['finished'] = time();
    shield_job_save($job);
    return $job;
}
