<?php
declare(strict_types=1);

// POST handlers. Each case ends with go() (redirect after POST).

$a = (string)($_POST['action'] ?? '');
$back = static fn(string $k, string $tab = '') => 'p=site&site=' . rawurlencode($k) . ($tab !== '' ? '&tab=' . $tab : '');
$queue = static function (string $type, string $k, array $params = []): string {
    if (shield_job_active($type, $k)) {
        flash(__('This task is already queued for %s.', $k), 'warn');
        return '';
    }
    return shield_job_add($type, ['site' => $k] + $params, 'admin');
};

switch ($a) {
    case 'logout':
        $_SESSION = [];
        session_destroy();
        go();

    // ---------------------------------------------------------------- backups
    case 'backup_now':
        $k = site_key_param();
        if ($queue('backup', $k)) {
            flash(__('Backup queued. It starts within a minute.'));
        }
        go($back($k, 'backups'));
    case 'backup_all':
        foreach (shield_sites() as $k => $s) {
            if (!empty($s['backup']) && !shield_job_active('backup', (string)$k)) {
                shield_job_add('backup', ['site' => (string)$k], 'admin');
            }
        }
        flash(__('Backups of all sites queued.'));
        go('p=jobs');
    case 'restore':
        $k = site_key_param();
        $scope = in_array($_POST['scope'] ?? '', ['all', 'files', 'db'], true) ? (string)$_POST['scope'] : 'all';
        $name = (string)($_POST['backup'] ?? '');
        if (trim((string)($_POST['confirm'] ?? '')) !== $k) {
            flash(__('To confirm, type the site key: %s', $k), 'err');
            go($back($k, 'backups'));
        }
        if (!in_array($name, array_column(shield_list_backups($k), 'name'), true)) {
            flash(__('No such backup.'), 'err');
            go($back($k, 'backups'));
        }
        $id = $queue('restore', $k, ['backup' => $name, 'scope' => $scope]);
        if ($id === '') {
            go('p=jobs');
        }
        shield_log('restore', "Restore requested {$k} from {$name} ({$scope}) by " . shield_client_ip());
        flash(__('Restore queued. A safety backup of the current state is taken first.'));
        go('p=job&id=' . $id);
    case 'delete_backup':
        $k = site_key_param();
        $name = (string)($_POST['backup'] ?? '');
        $list = shield_list_backups($k);
        if (count($list) <= 1) {
            flash(__('You cannot delete the only backup.'), 'err');
        } else {
            foreach ($list as $m) {
                if ($m['name'] === $name) {
                    shield_rrmdir($m['dir']);
                    shield_log('backup', "Deleted {$k}/{$name} by " . shield_client_ip());
                    flash(__('Deleted %s', $name));
                }
            }
        }
        go($back($k, 'backups'));
    case 'offsite_fetch':
        $k = site_key_param();
        $name = (string)($_POST['backup'] ?? '');
        $id = $queue('offsite_fetch', $k, ['backup' => $name]);
        go($id ? 'p=job&id=' . $id : $back($k, 'backups'));

    // ---------------------------------------------------------------- firewall
    case 'waf_on':
    case 'waf_off':
        $k = site_key_param();
        $msg = shield_site_waf_set(shield_site($k), $a === 'waf_on');
        flash($msg, preg_match('/cannot|different|не мога|друг/iu', $msg) ? 'err' : 'ok');
        go($back($k));
    case 'waf_exception':
        $k = site_key_param();
        $rule = (string)($_POST['rule'] ?? '');
        if (!isset(shield_waf_rule_catalog()[$rule])) {
            flash(__('Unknown rule.'), 'err');
            go('p=firewall');
        }
        shield_waf_add_exception($k, $rule, (string)($_POST['path'] ?? '/'));
        flash(__('Rule %s will no longer be checked on %s for this site.', $rule, (string)($_POST['path'] ?? '/')));
        go($back($k, 'firewall'));
    case 'waf_exception_remove':
        $k = site_key_param();
        $s = shield_settings();
        $i = (int)($_POST['index'] ?? -1);
        if (isset($s['sites'][$k]['waf_exceptions'][$i])) {
            array_splice($s['sites'][$k]['waf_exceptions'], $i, 1);
            shield_settings_save($s);
            flash(__('Exception removed.'));
        }
        go($back($k, 'firewall'));
    case 'unban':
        $f = basename((string)($_POST['file'] ?? ''));
        if (preg_match('/^[0-9a-f_]+\.json$/i', $f)) {
            @unlink(shield_path('waf/bans/' . $f));
            @unlink(shield_path('waf/strikes/' . $f));
            flash(__('IP address unbanned.'));
        }
        go('p=firewall');
    case 'list_add':
        $ip = trim((string)($_POST['ip'] ?? ''));
        $which = ($_POST['list'] ?? '') === 'allow' ? 'allow' : 'block';
        if (!shield_valid_ip_or_cidr($ip)) {
            flash(__('Invalid IP address.'), 'err');
        } elseif ($which === 'block' && shield_ip_in_list(shield_client_ip(), [$ip])) {
            flash(__('That would block your own IP address (%s).', shield_client_ip()), 'err');
        } else {
            $s = shield_settings();
            foreach (['allow', 'block'] as $w) {
                $s['waf'][$w] = array_values(array_filter((array)$s['waf'][$w], static fn($x) => ($x['ip'] ?? '') !== $ip));
            }
            $s['waf'][$which][] = ['ip' => $ip, 'note' => mb_substr(trim((string)($_POST['note'] ?? '')), 0, 100), 't' => time()];
            shield_settings_save($s);
            flash(($which === 'allow' ? __('Always allowed: %s', $ip) : __('Always blocked: %s', $ip)));
        }
        go('p=firewall');
    case 'list_remove':
        $ip = (string)($_POST['ip'] ?? '');
        $s = shield_settings();
        foreach (['allow', 'block'] as $w) {
            $s['waf'][$w] = array_values(array_filter((array)$s['waf'][$w], static fn($x) => ($x['ip'] ?? '') !== $ip));
        }
        shield_settings_save($s);
        flash(__('Removed %s', $ip));
        go('p=firewall');

    // ---------------------------------------------------------------- files
    case 'integrity_now':
        $k = site_key_param();
        if ($id = $queue('integrity', $k)) {
            flash(__('Full scan queued. It starts within a minute.'));
            go('p=job&id=' . $id);
        }
        go($back($k, 'files'));
    case 'integrity_accept':
        $k = site_key_param();
        $r = shield_integrity_accept($k);
        flash(__('Current files approved.') . (!empty($r['malware']) ? ' ' . __('%d suspicious files are still flagged.', count($r['malware'])) : ''));
        go($back($k, 'files'));
    case 'scan_ignore':
        $k = site_key_param();
        shield_scan_ignore($k, (string)($_POST['file'] ?? ''));
        flash(__('Marked as safe. It will be flagged again if its content changes.'));
        go($back($k, 'files'));
    case 'quarantine':
        $k = site_key_param();
        $rel = (string)($_POST['file'] ?? '');
        $rep = shield_integrity_report($k);
        try {
            shield_quarantine_file($k, $rel, (array)($rep['malware'][$rel]['rules'] ?? []));
            flash(__('%s moved to quarantine.', $rel));
        } catch (Throwable $e) {
            flash($e->getMessage(), 'err');
        }
        go($back($k, 'files'));
    case 'quarantine_restore':
        $k = site_key_param();
        try {
            $rel = shield_quarantine_restore($k, (string)($_POST['id'] ?? ''));
            flash(__('%s put back.', $rel));
        } catch (Throwable $e) {
            flash($e->getMessage(), 'err');
        }
        go($back($k, 'files'));
    case 'quarantine_delete':
        $k = site_key_param();
        shield_quarantine_delete($k, (string)($_POST['id'] ?? ''));
        flash(__('Deleted from quarantine.'));
        go($back($k, 'files'));

    // ---------------------------------------------------------------- audit
    case 'audit_now':
        $k = site_key_param();
        if ($id = $queue('audit', $k)) {
            flash(__('Audit queued. It starts within a minute.'));
            go('p=job&id=' . $id);
        }
        go($back($k, 'audit'));
    case 'audit_all':
        foreach (array_keys(shield_sites()) as $k) {
            if (!shield_job_active('audit', (string)$k)) {
                shield_job_add('audit', ['site' => (string)$k], 'admin');
            }
        }
        flash(__('Audits of all sites queued.'));
        go('p=jobs');

    // ---------------------------------------------------------------- sites
    case 'site_add':
        $s = shield_settings();
        $found = [];
        foreach (shield_discover_sites() as $d) {
            $found[$d['path']] = $d;
        }
        $added = 0;
        foreach ((array)($_POST['paths'] ?? []) as $path) {
            $path = (string)$path;
            if (!isset($found[$path])) {
                continue;
            }
            foreach ($s['sites'] as $x) {
                if ($x['path'] === $path) {
                    continue 2;
                }
            }
            $site = shield_site_from_discovery($found[$path]);
            $s['sites'][shield_site_key($site['title'], $s['sites'])] = $site;
            $added++;
        }
        $manual = trim((string)($_POST['manual_path'] ?? ''));
        if ($manual !== '') {
            $manual = rtrim(str_replace('\\', '/', $manual), '/');
            if (!is_dir($manual)) {
                flash(__('Folder does not exist: %s', $manual), 'err');
                go('p=site_add');
            }
            $platform = shield_detect_platform($manual);
            $domain = trim((string)($_POST['manual_domain'] ?? ''));
            $site = shield_site_from_discovery(['path' => shield_app_root($manual, $platform), 'domain' => $domain, 'platform' => $platform, 'db' => shield_detect_db($manual, $platform)]);
            $s['sites'][shield_site_key($site['title'], $s['sites'])] = $site;
            $added++;
        }
        if ($added) {
            shield_settings_save($s);
            flash(__('%d sites added. Next: enable the firewall on each site and take a first backup.', $added));
        } else {
            flash(__('Nothing selected.'), 'warn');
        }
        go();
    case 'site_save':
        $k = site_key_param();
        $s = shield_settings();
        $site = $s['sites'][$k];
        $in = (array)($_POST['site'] ?? []);
        $path = rtrim(str_replace('\\', '/', trim((string)($in['path'] ?? $site['path']))), '/');
        if (!is_dir($path)) {
            flash(__('Folder does not exist: %s', $path), 'err');
            go($back($k, 'settings'));
        }
        $url = trim((string)($in['url'] ?? ''));
        if ($url !== '' && !preg_match('#^https?://#', $url)) {
            $url = 'https://' . $url;
        }
        $site = array_replace($site, [
            'title' => trim((string)($in['title'] ?? '')) ?: $k,
            'url' => rtrim($url, '/'),
            'hosts' => array_map('strtolower', lines($in['hosts'] ?? '')),
            'path' => $path,
            'platform' => isset(SHIELD_PLATFORMS[$in['platform'] ?? '']) ? (string)$in['platform'] : $site['platform'],
            'databases' => lines($in['databases'] ?? ''),
            'db_patterns' => lines($in['db_patterns'] ?? ''),
            'exclude' => lines($in['exclude'] ?? ''),
            'upload_dirs' => array_map(static fn($d) => trim($d, '/'), lines($in['upload_dirs'] ?? '')),
            'waf_mode' => in_array($in['waf_mode'] ?? '', ['log', 'block', 'off'], true) ? (string)$in['waf_mode'] : null,
            'waf_skip_paths' => lines($in['waf_skip_paths'] ?? ''),
            'waf_disabled_rules' => array_values(array_intersect(lines($in['waf_disabled_rules'] ?? ''), array_keys(shield_waf_rule_catalog()))),
            'lockdown' => !empty($in['lockdown']),
            'banner' => !empty($in['banner']),
            'backup' => !empty($in['backup']),
        ]);
        $db = (array)($in['db'] ?? []);
        $site['db'] = [
            'host' => trim((string)($db['host'] ?? '')) ?: 'localhost',
            'port' => (int)($db['port'] ?? 3306) ?: 3306,
            'user' => trim((string)($db['user'] ?? '')),
            'pass' => (string)($db['pass'] ?? '') !== '' ? (string)$db['pass'] : (string)($site['db']['pass'] ?? ''),
        ];
        if ($site['db']['user'] === '') {
            $site['db'] = [];
        }
        if ($site['lockdown'] && !is_file(shield_path('waf/exec-' . $k . '.php'))) {
            shield_write_exec_allowlist($k, shield_snapshot($site + ['key' => $k])['code']);
        }
        $s['sites'][$k] = $site;
        shield_settings_save($s);
        flash(__('Site settings saved.'));
        go($back($k, 'settings'));
    case 'site_detect_db':
        $k = site_key_param();
        $site = shield_site($k);
        $db = shield_detect_db($site['path'], $site['platform']);
        if (!$db && ($site['platform'] === 'laravel')) {
            $db = shield_detect_db($site['path'] . '/public', 'laravel');
        }
        if (!$db) {
            flash(__('No database settings found in the application config.'), 'warn');
        } else {
            $s = shield_settings();
            $s['sites'][$k]['db'] = array_intersect_key($db, array_flip(['host', 'port', 'user', 'pass']));
            if (!in_array($db['name'], $s['sites'][$k]['databases'], true)) {
                $s['sites'][$k]['databases'][] = $db['name'];
            }
            shield_settings_save($s);
            flash(__('Found database %s (user %s).', $db['name'], $db['user']));
        }
        go($back($k, 'settings'));
    case 'site_test_db':
        $k = site_key_param();
        try {
            $site = shield_site($k);
            $dbs = shield_site_databases($site);
            foreach ($dbs as $d) {
                shield_db_connect($site, $d)->close();
            }
            flash($dbs ? __('Connected to: %s', implode(', ', $dbs)) : __('Connection works, but no databases are listed for this site.'), $dbs ? 'ok' : 'warn');
        } catch (Throwable $e) {
            flash(__('Database connection failed: %s', $e->getMessage()), 'err');
        }
        go($back($k, 'settings'));
    case 'site_remove':
        $k = site_key_param();
        if (trim((string)($_POST['confirm'] ?? '')) !== $k) {
            flash(__('To confirm, type the site key: %s', $k), 'err');
            go($back($k, 'settings'));
        }
        if (shield_site_waf_state(shield_site($k)) === 'on') {
            shield_site_waf_set(shield_site($k), false);
        }
        $s = shield_settings();
        unset($s['sites'][$k]);
        shield_settings_save($s);
        flash(__('Site %s removed from HostShield. Its backups stay in the data folder.', $k));
        go();

    // ---------------------------------------------------------------- settings
    case 'settings_save':
        $s = shield_settings();
        $in = $_POST;
        $section = (string)($in['section'] ?? '');
        $int = static fn($v, int $min, int $max, int $def): int => is_numeric($v) ? max($min, min($max, (int)$v)) : $def;
        $secret = static fn($new, $old): string => (string)$new !== '' ? (string)$new : (string)$old;
        switch ($section) {
            case 'general':
                $s['language'] = isset(SHIELD_LANGUAGES[$in['language'] ?? '']) || ($in['language'] ?? '') === 'auto' ? (string)$in['language'] : 'auto';
                $s['timezone'] = in_array($in['timezone'] ?? '', timezone_identifiers_list(), true) ? (string)$in['timezone'] : $s['timezone'];
                $s['dashboard_url'] = rtrim(trim((string)($in['dashboard_url'] ?? '')), '/');
                $s['monitor']['uptime_minutes'] = $int($in['uptime_minutes'] ?? 5, 1, 60, 5);
                $s['monitor']['integrity_minutes'] = $int($in['integrity_minutes'] ?? 60, 5, 1440, 60);
                $s['monitor']['audit_hours'] = $int($in['audit_hours'] ?? 24, 1, 168, 24);
                $s['monitor']['ssl_warn_days'] = $int($in['ssl_warn_days'] ?? 14, 1, 60, 14);
                $s['monitor']['auto_quarantine'] = !empty($in['auto_quarantine']);
                $s['updates']['check'] = !empty($in['update_check']);
                $s['banner']['enabled'] = !empty($in['banner_enabled']);
                $s['banner']['text'] = mb_substr(trim((string)($in['banner_text'] ?? '')), 0, 80) ?: 'Protected by HostShield';
                $s['banner']['show'] = in_array($in['banner_show'] ?? '', ['session', 'always', 'once'], true) ? (string)$in['banner_show'] : 'session';
                break;
            case 'firewall':
                $s['waf']['mode'] = ($in['mode'] ?? '') === 'block' ? 'block' : 'log';
                $s['waf']['rate_limit_per_min'] = $int($in['rate_limit_per_min'] ?? 600, 0, 100000, 600);
                $s['waf']['login_limit'] = $int($in['login_limit'] ?? 10, 1, 1000, 10);
                $s['waf']['login_window'] = $int($in['login_window'] ?? 600, 60, 86400, 600);
                $s['waf']['strikes_to_ban'] = $int($in['strikes_to_ban'] ?? 3, 1, 100, 3);
                $s['waf']['ban_minutes'] = $int($in['ban_minutes'] ?? 60, 1, 10080, 60);
                $s['waf']['block_exec_in_uploads'] = !empty($in['block_exec_in_uploads']);
                $s['waf']['wp_block_xmlrpc'] = !empty($in['wp_block_xmlrpc']);
                $s['waf']['wp_block_user_enum'] = !empty($in['wp_block_user_enum']);
                $s['waf']['trusted_proxies'] = array_values(array_filter(lines($in['trusted_proxies'] ?? ''), 'shield_valid_ip_or_cidr'));
                break;
            case 'backups':
                $s['backup']['enabled'] = !empty($in['enabled']);
                $s['backup']['hour'] = $int($in['hour'] ?? 3, 0, 23, 3);
                $s['backup']['keep_daily'] = $int($in['keep_daily'] ?? 7, 1, 365, 7);
                $s['backup']['keep_weekly'] = $int($in['keep_weekly'] ?? 4, 0, 104, 4);
                $s['backup']['keep_monthly'] = $int($in['keep_monthly'] ?? 3, 0, 120, 3);
                $s['backup']['max_file_mb'] = $int($in['max_file_mb'] ?? 500, 1, 100000, 500);
                $s['db']['host'] = trim((string)($in['db_host'] ?? '')) ?: 'localhost';
                $s['db']['port'] = $int($in['db_port'] ?? 3306, 1, 65535, 3306);
                $s['db']['user'] = trim((string)($in['db_user'] ?? ''));
                $s['db']['pass'] = $secret($in['db_pass'] ?? '', $s['db']['pass']);
                $o = &$s['backup']['offsite'];
                $o['type'] = in_array($in['offsite_type'] ?? '', ['none', 'ftp', 's3'], true) ? (string)$in['offsite_type'] : 'none';
                $o['ftp'] = [
                    'host' => trim((string)($in['ftp_host'] ?? '')), 'port' => $int($in['ftp_port'] ?? 21, 1, 65535, 21),
                    'user' => trim((string)($in['ftp_user'] ?? '')), 'pass' => $secret($in['ftp_pass'] ?? '', $o['ftp']['pass'] ?? ''),
                    'dir' => '/' . trim((string)($in['ftp_dir'] ?? 'shield-backups'), '/'), 'ssl' => !empty($in['ftp_ssl']),
                ];
                $o['s3'] = [
                    'endpoint' => trim((string)($in['s3_endpoint'] ?? '')), 'region' => trim((string)($in['s3_region'] ?? '')) ?: 'auto',
                    'bucket' => trim((string)($in['s3_bucket'] ?? '')), 'key' => trim((string)($in['s3_key'] ?? '')),
                    'secret' => $secret($in['s3_secret'] ?? '', $o['s3']['secret'] ?? ''),
                    'prefix' => trim((string)($in['s3_prefix'] ?? ''), '/') . '/', 'path_style' => !empty($in['s3_path_style']),
                ];
                unset($o);
                if (!empty($in['test'])) {
                    try {
                        flash(shield_offsite_test($s['backup']['offsite']));
                    } catch (Throwable $e) {
                        flash(__('Connection test failed: %s', $e->getMessage()), 'err');
                    }
                }
                break;
            case 'notifications':
                $n = &$s['notify'];
                $n['email'] = implode(', ', array_filter(lines($in['email'] ?? ''), static fn($x) => filter_var($x, FILTER_VALIDATE_EMAIL)));
                $n['email_enabled'] = !empty($in['email_enabled']);
                $n['ban_digest'] = isset(SHIELD_BAN_DIGEST[$in['ban_digest'] ?? '']) ? (string)$in['ban_digest'] : 'hourly';
                $n['max_per_day'] = $int($in['max_per_day'] ?? 0, 0, 1000, 0);
                $n['mail_from'] = filter_var(trim((string)($in['mail_from'] ?? '')), FILTER_VALIDATE_EMAIL) ?: '';
                $n['transport'] = ($in['transport'] ?? '') === 'smtp' ? 'smtp' : 'mail';
                $n['smtp'] = [
                    'host' => trim((string)($in['smtp_host'] ?? '')), 'port' => $int($in['smtp_port'] ?? 587, 1, 65535, 587),
                    'secure' => in_array($in['smtp_secure'] ?? '', ['tls', 'ssl', 'none'], true) ? (string)$in['smtp_secure'] : 'tls',
                    'user' => trim((string)($in['smtp_user'] ?? '')), 'pass' => $secret($in['smtp_pass'] ?? '', $n['smtp']['pass'] ?? ''),
                ];
                $n['telegram'] = ['token' => $secret($in['tg_token'] ?? '', $n['telegram']['token'] ?? ''), 'chat_id' => trim((string)($in['tg_chat'] ?? ''))];
                if (!empty($in['tg_clear'])) {
                    $n['telegram'] = ['token' => '', 'chat_id' => ''];
                }
                $hook = trim((string)($in['webhook_url'] ?? ''));
                $n['webhook'] = ['url' => preg_match('#^https://#', $hook) ? $hook : '', 'format' => in_array($in['webhook_format'] ?? '', ['discord', 'slack', 'generic'], true) ? (string)$in['webhook_format'] : 'discord'];
                foreach (array_keys(SHIELD_EVENTS) as $ev) {
                    $n['events'][$ev] = !empty($in['ev_' . $ev]);
                }
                unset($n);
                break;
            case 'security':
                $s['admin_allowed_ips'] = array_values(array_filter(lines($in['admin_allowed_ips'] ?? ''), 'shield_valid_ip_or_cidr'));
                if ($s['admin_allowed_ips'] && !shield_ip_in_list(shield_client_ip(), $s['admin_allowed_ips'])) {
                    flash(__('Your current IP (%s) must be in the list, or you would lock yourself out.', shield_client_ip()), 'err');
                    go('p=settings&tab=security');
                }
                $s['session_minutes'] = $int($in['session_minutes'] ?? 30, 5, 1440, 30);
                break;
            default:
                go('p=settings');
        }
        shield_settings_save($s);
        if (empty($in['test'])) {
            flash(__('Settings saved.'));
        }
        go('p=settings&tab=' . $section);
    case 'notify_test':
        $sent = shield_notify('test', __('Test alert'), __('If you can read this, alerts work.'));
        flash($sent ? __('Sent via: %s', implode(', ', $sent)) : __('No channel accepted the message. Check the settings and the log.'), $sent ? 'ok' : 'err');
        go('p=settings&tab=notifications');
    case 'update_check':
        $r = shield_update_check(true);
        $status = shield_update_status();
        flash(match (true) {
            (bool)$r => __('Latest release: %s', $r['version']),
            $status === 'disabled' => __('Update checks are turned off in Settings.'),
            $status === 'none' => __('No release has been published on GitHub yet.'),
            default => __('Could not reach GitHub.'),
        }, $r ? 'ok' : 'warn');
        go('p=about');

    // ---------------------------------------------------------------- account
    case 'totp_start':
        $_SESSION['totp_new'] = shield_base32_encode(random_bytes(20));
        go('p=settings&tab=security');
    case 'totp_enable':
        $secret = (string)($_SESSION['totp_new'] ?? '');
        if ($secret !== '' && shield_totp_verify($secret, (string)($_POST['code'] ?? ''))) {
            $admin['totp'] = $secret;
            $_SESSION['recovery_show'] = shield_recovery_codes_new($admin);
            shield_admin_save($admin);
            unset($_SESSION['totp_new']);
            flash(__('Two-factor authentication is on. Save the recovery codes below.'));
        } else {
            flash(__('Wrong code. Try again.'), 'err');
        }
        go('p=settings&tab=security');
    case 'totp_disable':
        if (password_verify((string)($_POST['password'] ?? ''), (string)$admin['hash'])) {
            $admin['totp'] = '';
            $admin['recovery'] = [];
            shield_admin_save($admin);
            flash(__('Two-factor authentication is off.'), 'warn');
        } else {
            flash(__('Wrong password.'), 'err');
        }
        go('p=settings&tab=security');
    case 'recovery_new':
        if (password_verify((string)($_POST['password'] ?? ''), (string)$admin['hash']) && !empty($admin['totp'])) {
            $_SESSION['recovery_show'] = shield_recovery_codes_new($admin);
            shield_admin_save($admin);
            flash(__('New recovery codes created. The old ones no longer work.'));
        } else {
            flash(__('Wrong password.'), 'err');
        }
        go('p=settings&tab=security');
    case 'password':
        if (!password_verify((string)($_POST['old'] ?? ''), (string)$admin['hash'])) {
            flash(__('Wrong current password.'), 'err');
        } elseif (strlen((string)($_POST['new'] ?? '')) < 12 || $_POST['new'] !== ($_POST['new2'] ?? '')) {
            flash(__('The new password must be at least 12 characters and match.'), 'err');
        } else {
            $admin['hash'] = password_hash((string)$_POST['new'], PASSWORD_DEFAULT);
            shield_admin_save($admin);
            flash(__('Password changed.'));
        }
        go('p=settings&tab=security');
}
