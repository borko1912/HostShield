<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';
require_once __DIR__ . '/notify.php';
require_once __DIR__ . '/offsite.php';

const SHIELD_SQL_SEP = '-- @@';

/** Connection with the site's own credentials, falling back to the global ones. */
function shield_db_connect(array $site, ?string $database = null): mysqli
{
    $global = (array)(shield_config()['db'] ?? []);
    $own = array_filter((array)($site['db'] ?? []), static fn($v) => $v !== '' && $v !== null);
    $c = !empty($own['user']) ? array_replace(['host' => 'localhost', 'port' => 3306, 'pass' => ''], $own) : $global;
    if (trim((string)($c['user'] ?? '')) === '') {
        throw new RuntimeException(__('No database user set for this site. Add it in the site settings.'));
    }
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $db = new mysqli((string)($c['host'] ?? 'localhost'), (string)$c['user'], (string)($c['pass'] ?? ''), (string)($database ?? ''), (int)($c['port'] ?? 3306) ?: 3306);
    $db->set_charset('utf8mb4');
    $db->query("SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO'");
    return $db;
}

/** All databases of a site: listed ones plus those matching db_patterns (SQL LIKE). */
function shield_site_databases(array $site): array
{
    $dbs = array_values(array_filter(array_map('strval', (array)($site['databases'] ?? []))));
    $patterns = array_filter((array)($site['db_patterns'] ?? []));
    if ($patterns) {
        $conn = shield_db_connect($site);
        foreach ($patterns as $p) {
            $res = $conn->query("SHOW DATABASES LIKE '" . $conn->real_escape_string((string)$p) . "'");
            while ($row = $res->fetch_row()) {
                $dbs[] = (string)$row[0];
            }
        }
        $conn->close();
    }
    return array_values(array_unique($dbs));
}

function shield_strip_definer(string $sql): string
{
    return (string)preg_replace('/\sDEFINER\s*=\s*(`[^`]*`|\'[^\']*\'|\S+)@(`[^`]*`|\'[^\']*\'|\S+)/i', '', $sql);
}

/** Dumps a database to .sql.gz. Every statement ends with a "-- @@" line, which makes restore simple and safe. */
function shield_dump_database(array $site, string $database, string $file): array
{
    $db = shield_db_connect($site, $database);
    $gz = gzopen($file, 'wb6');
    if (!$gz) {
        throw new RuntimeException('Cannot write ' . $file);
    }
    $w = static function (string $sql) use ($gz): void {
        gzwrite($gz, $sql . ";\n" . SHIELD_SQL_SEP . "\n");
    };
    gzwrite($gz, '-- HostShield ' . SHIELD_VERSION . ' dump: ' . $database . ' @ ' . date('c') . "\n");
    $w('SET NAMES utf8mb4');
    $w('SET FOREIGN_KEY_CHECKS=0');
    $w("SET SQL_MODE='NO_AUTO_VALUE_ON_ZERO'");

    $tables = [];
    $views = [];
    $res = $db->query('SHOW FULL TABLES');
    while ($r = $res->fetch_row()) {
        if (strtoupper((string)$r[1]) === 'VIEW') {
            $views[] = (string)$r[0];
        } else {
            $tables[] = (string)$r[0];
        }
    }

    $rowsTotal = 0;
    foreach ($tables as $t) {
        $q = '`' . str_replace('`', '``', $t) . '`';
        $create = $db->query('SHOW CREATE TABLE ' . $q)->fetch_row()[1];
        $w('DROP TABLE IF EXISTS ' . $q);
        $w((string)$create);

        $res = $db->query('SELECT * FROM ' . $q, MYSQLI_USE_RESULT);
        $fields = $res->fetch_fields();
        $binary = [];
        $bit = [];
        foreach ($fields as $i => $f) {
            $binary[$i] = ((int)$f->charsetnr === 63 && in_array((int)$f->type, [MYSQLI_TYPE_BLOB, MYSQLI_TYPE_TINY_BLOB, MYSQLI_TYPE_MEDIUM_BLOB, MYSQLI_TYPE_LONG_BLOB, MYSQLI_TYPE_STRING, MYSQLI_TYPE_VAR_STRING, MYSQLI_TYPE_GEOMETRY], true));
            $bit[$i] = (int)$f->type === MYSQLI_TYPE_BIT; // mysqlnd returns BIT as a decimal string
        }
        $cols = '(' . implode(',', array_map(static fn($f) => '`' . str_replace('`', '``', $f->name) . '`', $fields)) . ')';
        $prefix = 'INSERT INTO ' . $q . ' ' . $cols . ' VALUES ';
        $batch = '';
        while ($row = $res->fetch_row()) {
            $vals = [];
            foreach ($row as $i => $v) {
                if ($v === null) {
                    $vals[] = 'NULL';
                } elseif ($bit[$i] && ctype_digit((string)$v)) {
                    $vals[] = (string)$v;
                } elseif ($binary[$i]) {
                    $vals[] = $v === '' ? "''" : '0x' . bin2hex($v);
                } else {
                    $vals[] = "'" . $db->real_escape_string((string)$v) . "'";
                }
            }
            $tuple = '(' . implode(',', $vals) . ')';
            if ($batch !== '' && strlen($batch) + strlen($tuple) > 1000000) {
                $w($prefix . $batch);
                $batch = '';
            }
            $batch .= ($batch === '' ? '' : ',') . $tuple;
            $rowsTotal++;
        }
        if ($batch !== '') {
            $w($prefix . $batch);
        }
        $res->free();
    }

    foreach ($views as $v) {
        $q = '`' . str_replace('`', '``', $v) . '`';
        $create = shield_strip_definer((string)$db->query('SHOW CREATE VIEW ' . $q)->fetch_row()[1]);
        $create = (string)preg_replace('/\sSQL SECURITY DEFINER/i', ' SQL SECURITY INVOKER', $create);
        $w('DROP VIEW IF EXISTS ' . $q);
        $w($create);
    }

    $res = $db->query('SHOW TRIGGERS');
    $triggers = [];
    while ($r = $res->fetch_assoc()) {
        $triggers[] = (string)$r['Trigger'];
    }
    foreach ($triggers as $tr) {
        $q = '`' . str_replace('`', '``', $tr) . '`';
        $row = $db->query('SHOW CREATE TRIGGER ' . $q)->fetch_assoc();
        $w('DROP TRIGGER IF EXISTS ' . $q);
        $w(shield_strip_definer((string)$row['SQL Original Statement']));
    }

    $w('SET FOREIGN_KEY_CHECKS=1');
    gzwrite($gz, "-- HostShield dump complete\n");
    gzclose($gz);
    $db->close();
    return ['tables' => count($tables), 'views' => count($views), 'triggers' => count($triggers), 'rows' => $rowsTotal];
}

function shield_restore_database(array $site, string $database, string $file): int
{
    $db = shield_db_connect($site);
    try {
        $db->select_db($database);
    } catch (mysqli_sql_exception) {
        try {
            $db->query('CREATE DATABASE `' . str_replace('`', '``', $database) . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
            $db->select_db($database);
        } catch (mysqli_sql_exception) {
            throw new RuntimeException(__('Database %s is missing. Create it again in your hosting panel (and give the database user access), then run the restore again.', $database));
        }
    }
    $gz = gzopen($file, 'rb');
    if (!$gz) {
        throw new RuntimeException('Cannot open ' . $file);
    }
    // The dump must be complete before we touch the database.
    $complete = false;
    while (($line = gzgets($gz)) !== false) {
        if (str_starts_with($line, '-- HostShield dump complete') || str_starts_with($line, '-- Shield dump complete')) {
            $complete = true;
        }
    }
    if (!$complete) {
        throw new RuntimeException(__('Dump %s is incomplete. Restore stopped.', basename($file)));
    }
    gzrewind($gz);

    $db->query('SET FOREIGN_KEY_CHECKS=0');
    $res = $db->query('SHOW FULL TABLES');
    $drop = [];
    while ($r = $res->fetch_row()) {
        $drop[] = [(string)$r[0], strtoupper((string)$r[1]) === 'VIEW'];
    }
    foreach ($drop as [$name, $isView]) {
        $db->query(($isView ? 'DROP VIEW IF EXISTS `' : 'DROP TABLE IF EXISTS `') . str_replace('`', '``', $name) . '`');
    }

    $stmt = '';
    $count = 0;
    while (($line = gzgets($gz)) !== false) {
        if (rtrim($line, "\r\n") === SHIELD_SQL_SEP) {
            $sql = rtrim($stmt);
            $sql = str_ends_with($sql, ';') ? substr($sql, 0, -1) : $sql;
            if (trim($sql) !== '') {
                try {
                    $db->query($sql);
                } catch (mysqli_sql_exception $e) {
                    throw new RuntimeException('SQL error during restore (' . $database . '): ' . $e->getMessage() . ' | ' . mb_substr($sql, 0, 160));
                }
                $count++;
            }
            $stmt = '';
            continue;
        }
        if ($stmt === '' && str_starts_with($line, '-- ')) {
            continue;
        }
        $stmt .= $line;
    }
    gzclose($gz);
    $db->query('SET FOREIGN_KEY_CHECKS=1');
    $db->close();
    return $count;
}

function shield_backup_root(string $siteKey): string
{
    return shield_dir('backups/' . $siteKey);
}

/** Backups of a site, newest first. */
function shield_list_backups(string $siteKey): array
{
    $root = shield_path('backups/' . $siteKey);
    $out = [];
    foreach (is_dir($root) ? (array)scandir($root) : [] as $name) {
        $name = (string)$name;
        if ($name === '.' || $name === '..' || str_ends_with($name, '.partial')) {
            continue;
        }
        $m = shield_json_read($root . '/' . $name . '/manifest.json');
        if (!$m) {
            continue;
        }
        $m['name'] = $name;
        $m['dir'] = $root . '/' . $name;
        $out[] = $m;
    }
    usort($out, static fn($a, $b) => strcmp($b['name'], $a['name']));
    return $out;
}

/** Full backup (files + databases). $kind: daily | manual | pre-restore */
function shield_backup_site(string $siteKey, string $kind = 'daily', ?callable $say = null): array
{
    $site = shield_site($siteKey);
    if (!is_dir($site['path'])) {
        throw new RuntimeException(__('Site folder does not exist: %s', $site['path']));
    }
    if (!class_exists('ZipArchive')) {
        throw new RuntimeException(__('PHP zip extension is missing. Enable it in your hosting panel (PHP extensions).'));
    }
    @set_time_limit(0);
    $say ??= static fn(string $m) => null;
    $started = microtime(true);
    $name = date('Y-m-d_His') . '_' . $kind;
    $final = shield_backup_root($siteKey) . '/' . $name;
    $work = $final . '.partial';
    shield_rrmdir($work);
    shield_dir('backups/' . $siteKey . '/' . $name . '.partial');
    shield_log('backup', "Start {$siteKey} ({$kind})");

    try {
        $say(__('Archiving files...'));
        $zipFile = $work . '/files.zip';
        $zip = new ZipArchive();
        if ($zip->open($zipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            throw new RuntimeException('Cannot create ZIP');
        }
        $max = (int)(shield_config()['backup']['max_file_mb'] ?? 500) * 1048576;
        $count = 0;
        $bytes = 0;
        $skipped = [];
        $skippedPaths = [];
        $pending = 0;
        foreach (shield_walk($site) as $rel => $f) {
            if ($f->isDir()) {
                $zip->addEmptyDir($rel);
                continue;
            }
            if (!$f->isReadable()) {
                $skipped[] = $rel . ' (no permission)';
                $skippedPaths[] = $rel;
                continue;
            }
            if ($f->getSize() > $max) {
                $skipped[] = $rel . ' (' . shield_human_size($f->getSize()) . ')';
                $skippedPaths[] = $rel;
                continue;
            }
            $zip->addFile($f->getPathname(), $rel);
            $count++;
            $bytes += $f->getSize();
            // ZipArchive keeps every added file open until close(), so flush periodically.
            if (++$pending >= 2000) {
                $zip->close();
                $zip->open($zipFile);
                $pending = 0;
            }
        }
        $zip->setArchiveComment('HostShield ' . $siteKey . ' ' . $name);
        if (!$zip->close()) {
            throw new RuntimeException('ZIP write error (disk full?)');
        }
        $zcheck = new ZipArchive();
        if ($zcheck->open($zipFile, ZipArchive::CHECKCONS) !== true) {
            throw new RuntimeException('ZIP archive failed the integrity check');
        }
        $zcheck->close();

        $manifest = [
            'site' => $siteKey,
            'kind' => $kind,
            'created' => time(),
            'created_iso' => date('c'),
            'source_path' => $site['path'],
            'platform' => $site['platform'],
            'shield_version' => SHIELD_VERSION,
            'files' => [
                'file' => 'files.zip',
                'count' => $count,
                'original_bytes' => $bytes,
                'size' => filesize($zipFile),
                'sha256' => hash_file('sha256', $zipFile),
                'skipped' => $skipped,
                'skipped_paths' => $skippedPaths,
            ],
            'databases' => [],
        ];

        foreach (shield_site_databases($site) as $database) {
            $say(__('Dumping database %s...', $database));
            $safe = preg_replace('/[^A-Za-z0-9_.-]/', '_', $database);
            $sqlFile = $work . '/db-' . $safe . '.sql.gz';
            try {
                $stats = shield_dump_database($site, $database, $sqlFile);
            } catch (mysqli_sql_exception $e) {
                // Safety backup before a restore: an attacker may have dropped the database; carry on.
                if ($kind !== 'pre-restore' || (int)$e->getCode() !== 1049) {
                    throw $e;
                }
                @unlink($sqlFile);
                $manifest['missing_databases'][] = $database;
                continue;
            }
            $manifest['databases'][] = $stats + [
                'name' => $database,
                'file' => basename($sqlFile),
                'size' => filesize($sqlFile),
                'sha256' => hash_file('sha256', $sqlFile),
            ];
        }

        $manifest['duration'] = round(microtime(true) - $started, 1);
        $manifest['total_size'] = $manifest['files']['size'] + array_sum(array_column($manifest['databases'], 'size'));
        $manifest['status'] = 'ok';
        shield_json_write($work . '/manifest.json', $manifest);
        if (!@rename($work, $final)) {
            throw new RuntimeException('Cannot finalize the backup');
        }
    } catch (Throwable $e) {
        shield_rrmdir($work);
        shield_log('backup', "ERROR {$siteKey}: " . $e->getMessage());
        throw $e;
    }

    shield_log('backup', "OK {$siteKey}: {$count} files, " . count($manifest['databases']) . ' databases, ' . shield_human_size($manifest['total_size']) . ", {$manifest['duration']} s");
    $manifest['name'] = $name;
    $manifest['dir'] = $final;
    $manifest['pruned'] = shield_prune_backups($siteKey);

    if ($kind !== 'pre-restore' && shield_offsite_enabled()) {
        $say(__('Copying to off-site storage...'));
        try {
            shield_offsite_upload($siteKey, $name);
            shield_offsite_prune($siteKey);
            $manifest['offsite'] = true;
        } catch (Throwable $e) {
            shield_log('offsite', 'ERROR ' . $siteKey . ': ' . $e->getMessage());
            shield_notify('backup_failed', __('Off-site copy failed: %s', $site['title']), $e->getMessage());
            $manifest['offsite_error'] = $e->getMessage();
        }
    }
    return $manifest;
}

/**
 * Grandfather-father-son retention.
 * $items: name => unix time. Keeps the newest $daily, plus the newest backup of each of the
 * last $weekly weeks and $monthly months. Returns the names to keep.
 */
function shield_retention_keep(array $items, int $daily, int $weekly, int $monthly): array
{
    arsort($items);
    $keep = [];
    $weeks = [];
    $months = [];
    $i = 0;
    foreach ($items as $name => $t) {
        if ($i++ < max(1, $daily)) {
            $keep[$name] = true;
        }
        $w = date('o-W', (int)$t);
        if (!isset($weeks[$w]) && count($weeks) < $weekly) {
            $weeks[$w] = true;
            $keep[$name] = true;
        }
        $m = date('Y-m', (int)$t);
        if (!isset($months[$m]) && count($months) < $monthly) {
            $months[$m] = true;
            $keep[$name] = true;
        }
    }
    return array_keys($keep);
}

/** Time of a backup from its folder name (Y-m-d_His_kind). */
function shield_backup_time(string $name): int
{
    return preg_match('/^(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})(\d{2})_/', $name, $m) ? (int)strtotime("{$m[1]} {$m[2]}:{$m[3]}:{$m[4]}") : 0;
}

function shield_prune_backups(string $siteKey): array
{
    $b = (array)(shield_config()['backup'] ?? []);
    $all = shield_list_backups($siteKey);
    $regular = [];
    $pre = [];
    foreach ($all as $m) {
        if (($m['kind'] ?? '') === 'pre-restore') {
            $pre[] = $m;
        } else {
            $regular[$m['name']] = (int)$m['created'];
        }
    }
    $keep = array_flip(shield_retention_keep($regular, (int)($b['keep_daily'] ?? 7), (int)($b['keep_weekly'] ?? 4), (int)($b['keep_monthly'] ?? 3)));
    $removed = [];
    foreach ($all as $i => $m) {
        $drop = ($m['kind'] ?? '') === 'pre-restore'
            ? array_search($m, $pre, true) >= max(1, (int)($b['keep_pre_restore'] ?? 3))
            : !isset($keep[$m['name']]);
        if ($drop) {
            shield_rrmdir($m['dir']);
            $removed[] = $m['name'];
            shield_log('backup', "Removed old backup {$siteKey}/{$m['name']}");
        }
    }
    // Leftovers of crashed runs older than 12 hours.
    foreach ((array)glob(shield_path('backups/' . $siteKey) . '/*.partial') as $p) {
        if (time() - (int)filemtime((string)$p) > 43200) {
            shield_rrmdir((string)$p);
        }
    }
    return $removed;
}

function shield_verify_backup(array $m): array
{
    $problems = [];
    $check = static function (string $file, string $sha) use (&$problems, $m): void {
        $p = $m['dir'] . '/' . $file;
        if (!is_file($p)) {
            $problems[] = $file . ' ' . __('is missing');
        } elseif (!hash_equals($sha, (string)hash_file('sha256', $p))) {
            $problems[] = $file . ' ' . __('is corrupted (checksum)');
        }
    };
    $check((string)$m['files']['file'], (string)$m['files']['sha256']);
    foreach ((array)$m['databases'] as $d) {
        $check((string)$d['file'], (string)$d['sha256']);
    }
    return $problems;
}

/**
 * Restore. $scope: all | files | db
 * Takes a safety backup of the current state first.
 */
function shield_restore(string $siteKey, string $backupName, string $scope = 'all', ?callable $progress = null): array
{
    $site = shield_site($siteKey);
    $say = static function (string $msg) use ($progress, $siteKey): void {
        shield_log('restore', $siteKey . ': ' . $msg);
        $progress && $progress($msg);
    };
    $m = null;
    foreach (shield_list_backups($siteKey) as $b) {
        if ($b['name'] === $backupName) {
            $m = $b;
        }
    }
    if (!$m) {
        throw new RuntimeException(__('No such backup: %s', $backupName));
    }
    $say(__('Verifying archive %s', $backupName));
    if ($problems = shield_verify_backup($m)) {
        throw new RuntimeException(__('The archive is damaged: %s', implode('; ', $problems)));
    }

    $say(__('Safety backup of the current state...'));
    $pre = shield_backup_site($siteKey, 'pre-restore');
    $say(__('Safety backup ready: %s', $pre['name']));

    $flag = shield_dir('waf/maintenance') . '/' . $siteKey;
    touch($flag);
    $result = ['pre_restore' => $pre['name'], 'files' => null, 'databases' => []];
    try {
        if ($scope === 'all' || $scope === 'db') {
            foreach ((array)$m['databases'] as $d) {
                $say(__('Restoring database %s...', $d['name']));
                $n = shield_restore_database($site, (string)$d['name'], $m['dir'] . '/' . $d['file']);
                $result['databases'][] = ['name' => $d['name'], 'statements' => $n];
            }
        }
        if ($scope === 'all' || $scope === 'files') {
            $say(__('Restoring files...'));
            $result['files'] = shield_restore_files($site, $m['dir'] . '/' . $m['files']['file'], (array)($m['files']['skipped_paths'] ?? []));
            $say(__('Files: %d written, %d removed (not in the archive)', $result['files']['written'], $result['files']['removed']));
        }
    } finally {
        @unlink($flag);
    }
    if ($scope !== 'db') {
        require_once __DIR__ . '/monitor.php';
        $rep = shield_integrity_accept($siteKey);
        $say(__('File check: %d suspicious', count((array)($rep['malware'] ?? []))));
    }
    $say(__('Done.'));
    shield_notify('restore', __('Site restored: %s', $site['title']), __("Site: %s\nFrom backup: %s\nScope: %s\nSafety copy: %s", $site['title'], $backupName, $scope, $pre['name']));
    return $result;
}

/**
 * Syncs the site folder with the archive: writes every file from the archive and removes
 * files that are not in it (such as shells an attacker uploaded).
 * Excluded paths (logs, nested sites, HostShield itself) are left alone.
 */
function shield_restore_files(array $site, string $zipFile, array $keepPaths = []): array
{
    $root = $site['path'];
    $zip = new ZipArchive();
    if ($zip->open($zipFile) !== true) {
        throw new RuntimeException('Cannot open the archive');
    }
    $staging = shield_dir('staging') . '/' . $site['key'] . '-' . date('YmdHis');
    shield_rrmdir($staging);
    mkdir($staging, 0700, true);

    $inArchive = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $n = (string)$zip->getNameIndex($i);
        $clean = trim(str_replace('\\', '/', $n), '/');
        if ($clean === '' || str_contains('/' . $clean . '/', '/../') || str_starts_with($n, '/') || preg_match('/^[a-z]:/i', $n)) {
            throw new RuntimeException('Unsafe path in the archive: ' . $n);
        }
        $inArchive[$clean] = str_ends_with($n, '/');
    }
    if (!$zip->extractTo($staging)) {
        $zip->close();
        shield_rrmdir($staging);
        throw new RuntimeException(__('Extraction failed (disk space?)'));
    }
    $zip->close();

    $written = 0;
    $removed = 0;
    try {
        foreach ($inArchive as $rel => $isDir) {
            $target = $root . '/' . $rel;
            if ($isDir) {
                if (is_file($target) || is_link($target)) {
                    @unlink($target);
                }
                is_dir($target) || mkdir($target, 0755, true);
                continue;
            }
            $src = $staging . '/' . $rel;
            if (is_dir($target) && !is_link($target)) {
                shield_rrmdir($target);
            }
            is_dir(dirname($target)) || mkdir(dirname($target), 0755, true);
            if (!@rename($src, $target) && !@copy($src, $target)) {
                throw new RuntimeException('Cannot write ' . $rel);
            }
            @chmod($target, 0644);
            $written++;
        }

        $keep = array_flip($keepPaths);
        $dirs = [];
        foreach (shield_walk($site) as $rel => $f) {
            if (isset($inArchive[$rel]) || isset($keep[$rel])) {
                continue;
            }
            if ($f->isDir()) {
                $dirs[] = $f->getPathname();
            } elseif (@unlink($f->getPathname())) {
                $removed++;
            }
        }
        rsort($dirs);
        foreach ($dirs as $d) {
            @rmdir($d);
        }
    } finally {
        shield_rrmdir($staging);
    }
    return ['written' => $written, 'removed' => $removed];
}
