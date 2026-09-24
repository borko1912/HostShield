<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';
require_once __DIR__ . '/s3.php';

// Off-site copies of backups: FTP/FTPS or S3-compatible storage.
// Layout on the remote side: <dir or prefix>/<site>/<backup name>/<files>

function shield_offsite_type(): string
{
    return (string)(shield_config()['backup']['offsite']['type'] ?? 'none');
}

function shield_offsite_enabled(): bool
{
    return in_array(shield_offsite_type(), ['ftp', 's3'], true);
}

// ------------------------------------------------------------------ FTP

function shield_ftp(?array $o = null): \FTP\Connection
{
    $o ??= (array)shield_config()['backup']['offsite']['ftp'];
    if (!function_exists('ftp_connect')) {
        throw new RuntimeException(__('PHP ftp extension is missing'));
    }
    $conn = !empty($o['ssl']) && function_exists('ftp_ssl_connect')
        ? @ftp_ssl_connect((string)$o['host'], (int)($o['port'] ?? 21), 30)
        : @ftp_connect((string)$o['host'], (int)($o['port'] ?? 21), 30);
    if (!$conn || !@ftp_login($conn, (string)$o['user'], (string)$o['pass'])) {
        throw new RuntimeException(__('FTP login failed to %s', (string)$o['host']));
    }
    ftp_pasv($conn, true);
    return $conn;
}

function shield_ftp_mkdirs(\FTP\Connection $c, string $dir): void
{
    $path = '';
    foreach (array_filter(explode('/', $dir), 'strlen') as $part) {
        $path .= '/' . $part;
        if (!@ftp_chdir($c, $path)) {
            @ftp_mkdir($c, $path);
        }
    }
}

function shield_ftp_base(string $siteKey): string
{
    return rtrim((string)(shield_config()['backup']['offsite']['ftp']['dir'] ?? '/shield-backups'), '/') . '/' . $siteKey;
}

function shield_s3_base(string $siteKey): string
{
    $p = ltrim((string)(shield_config()['backup']['offsite']['s3']['prefix'] ?? ''), '/');
    return ($p !== '' ? rtrim($p, '/') . '/' : '') . $siteKey;
}

// ------------------------------------------------------------------ operations

function shield_offsite_upload(string $siteKey, string $name): void
{
    $local = shield_path('backups/' . $siteKey . '/' . $name);
    $files = array_values(array_filter((array)scandir($local), static fn($f) => is_file($local . '/' . $f)));
    // The manifest goes last: a remote backup without a manifest is incomplete and ignored.
    usort($files, static fn($a, $b) => ($a === 'manifest.json') <=> ($b === 'manifest.json'));
    if (shield_offsite_type() === 's3') {
        $base = shield_s3_base($siteKey) . '/' . $name;
        foreach ($files as $f) {
            shield_s3_put_file($base . '/' . $f, $local . '/' . $f);
        }
    } else {
        $base = shield_ftp_base($siteKey) . '/' . $name;
        $c = shield_ftp();
        try {
            shield_ftp_mkdirs($c, $base);
            foreach ($files as $f) {
                if (!@ftp_put($c, $base . '/' . $f, $local . '/' . $f, FTP_BINARY)) {
                    throw new RuntimeException(__('FTP upload failed: %s', $f));
                }
            }
        } finally {
            ftp_close($c);
        }
    }
    shield_log('offsite', "Uploaded {$siteKey}/{$name}");
}

/** Remote backups of a site: name => manifest (or [] when the manifest could not be read). */
function shield_offsite_list(string $siteKey): array
{
    $out = [];
    if (shield_offsite_type() === 's3') {
        $l = shield_s3_list(shield_s3_base($siteKey) . '/');
        foreach ($l['keys'] as $key => $size) {
            if (preg_match('#/([^/]+)/manifest\.json$#', $key, $m)) {
                $out[$m[1]] = [];
            }
        }
    } elseif (shield_offsite_type() === 'ftp') {
        $c = shield_ftp();
        try {
            foreach ((array)@ftp_nlist($c, shield_ftp_base($siteKey)) as $d) {
                $d = basename((string)$d);
                if (preg_match('/^\d{4}-\d{2}-\d{2}_\d{6}_[a-z-]+$/', $d) && @ftp_size($c, shield_ftp_base($siteKey) . '/' . $d . '/manifest.json') > 0) {
                    $out[$d] = [];
                }
            }
        } finally {
            ftp_close($c);
        }
    }
    krsort($out);
    return $out;
}

/** Applies the retention policy on the remote side. */
function shield_offsite_prune(string $siteKey): array
{
    $b = (array)shield_config()['backup'];
    $names = [];
    foreach (array_keys(shield_offsite_list($siteKey)) as $n) {
        if (!str_ends_with($n, '_pre-restore')) {
            $names[$n] = shield_backup_time($n);
        }
    }
    $keep = array_flip(shield_retention_keep($names, (int)$b['keep_daily'], (int)$b['keep_weekly'], (int)$b['keep_monthly']));
    $removed = [];
    foreach (array_keys($names) as $n) {
        if (isset($keep[$n])) {
            continue;
        }
        if (shield_offsite_type() === 's3') {
            foreach (array_keys(shield_s3_list(shield_s3_base($siteKey) . '/' . $n . '/')['keys']) as $key) {
                shield_s3_delete($key);
            }
        } else {
            $c = shield_ftp();
            try {
                $dir = shield_ftp_base($siteKey) . '/' . $n;
                foreach ((array)@ftp_nlist($c, $dir) as $f) {
                    @ftp_delete($c, $dir . '/' . basename((string)$f));
                }
                @ftp_rmdir($c, $dir);
            } finally {
                ftp_close($c);
            }
        }
        $removed[] = $n;
        shield_log('offsite', "Removed old remote backup {$siteKey}/{$n}");
    }
    return $removed;
}

/** Downloads a remote backup into the local backup folder (for restore after losing the server). */
function shield_offsite_fetch(string $siteKey, string $name, ?callable $say = null): string
{
    if (!preg_match('/^\d{4}-\d{2}-\d{2}_\d{6}_[a-z-]+$/', $name)) {
        throw new RuntimeException('Invalid backup name');
    }
    $say ??= static fn(string $m) => null;
    $final = shield_backup_root($siteKey) . '/' . $name;
    if (is_file($final . '/manifest.json')) {
        return $final;
    }
    $work = $final . '.partial';
    shield_rrmdir($work);
    mkdir($work, 0700, true);
    try {
        if (shield_offsite_type() === 's3') {
            $base = shield_s3_base($siteKey) . '/' . $name . '/';
            foreach (array_keys(shield_s3_list($base)['keys']) as $key) {
                $file = basename($key);
                if (preg_match('/^(files\.zip|manifest\.json|db-[A-Za-z0-9_.-]+\.sql\.gz)$/', $file)) {
                    $say(__('Downloading %s...', $file));
                    shield_s3_get_file($key, $work . '/' . $file);
                }
            }
        } else {
            $c = shield_ftp();
            try {
                $dir = shield_ftp_base($siteKey) . '/' . $name;
                foreach ((array)@ftp_nlist($c, $dir) as $f) {
                    $file = basename((string)$f);
                    if (preg_match('/^(files\.zip|manifest\.json|db-[A-Za-z0-9_.-]+\.sql\.gz)$/', $file)) {
                        $say(__('Downloading %s...', $file));
                        if (!@ftp_get($c, $work . '/' . $file, $dir . '/' . $file, FTP_BINARY)) {
                            throw new RuntimeException(__('FTP download failed: %s', $file));
                        }
                    }
                }
            } finally {
                ftp_close($c);
            }
        }
        $m = shield_json_read($work . '/manifest.json');
        if (!$m) {
            throw new RuntimeException(__('The remote backup has no manifest'));
        }
        $m['dir'] = $work;
        if ($problems = shield_verify_backup($m)) {
            throw new RuntimeException(__('The archive is damaged: %s', implode('; ', $problems)));
        }
        rename($work, $final);
    } catch (Throwable $e) {
        shield_rrmdir($work);
        throw $e;
    }
    shield_log('offsite', "Downloaded {$siteKey}/{$name}");
    return $final;
}

/** Connection test from the settings page: writes, reads back and deletes a small file. */
function shield_offsite_test(array $offsite): string
{
    $probe = 'hostshield-test-' . bin2hex(random_bytes(4)) . '.txt';
    $body = 'HostShield connection test ' . date('c');
    if (($offsite['type'] ?? '') === 's3') {
        $c = (array)$offsite['s3'];
        $key = (($p = trim((string)$c['prefix'], '/')) !== '' ? $p . '/' : '') . $probe;
        shield_s3_put($key, $body, $c);
        $back = shield_s3_get($key, $c);
        shield_s3_delete($key, $c);
        if ($back !== $body) {
            throw new RuntimeException(__('Uploaded, but could not read the file back'));
        }
        return __('S3 connection works (write, read, delete).');
    }
    if (($offsite['type'] ?? '') === 'ftp') {
        $o = (array)$offsite['ftp'];
        $c = shield_ftp($o);
        try {
            $dir = rtrim((string)$o['dir'], '/');
            shield_ftp_mkdirs($c, $dir);
            $tmp = tempnam(sys_get_temp_dir(), 'hs');
            file_put_contents($tmp, $body);
            $ok = @ftp_put($c, $dir . '/' . $probe, $tmp, FTP_BINARY);
            @unlink($tmp);
            if (!$ok) {
                throw new RuntimeException(__('Logged in, but cannot write to %s', $dir));
            }
            @ftp_delete($c, $dir . '/' . $probe);
        } finally {
            ftp_close($c);
        }
        return __('FTP connection works (login, write, delete).');
    }
    return __('Off-site copies are switched off.');
}
