<?php
declare(strict_types=1);

// HostShield dashboard — front controller.

if (PHP_VERSION_ID < 80100) {
    http_response_code(500);
    exit('HostShield needs PHP 8.1 or newer. This site runs PHP ' . PHP_VERSION . '. Change the PHP version in your hosting panel.');
}

require_once __DIR__ . '/lib/core.php';
require_once __DIR__ . '/lib/auth.php';
require_once __DIR__ . '/lib/notify.php';
require_once __DIR__ . '/lib/backup.php';
require_once __DIR__ . '/lib/monitor.php';
require_once __DIR__ . '/lib/audit.php';
require_once __DIR__ . '/lib/jobs.php';
require_once __DIR__ . '/lib/waf_admin.php';
require_once __DIR__ . '/lib/detect.php';
require_once __DIR__ . '/lib/updates.php';
require_once __DIR__ . '/app/ui.php';

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
header('Cache-Control: no-store');

$p = (string)($_GET['p'] ?? 'home');

if (!shield_installed()) {
    shield_session_start(); // before any output: hosts without output buffering cannot send the cookie later
    require __DIR__ . '/app/install.php';
    exit;
}

try {
    $cfg = shield_config();
    shield_migrate();
    $cfg = shield_config();
} catch (Throwable $e) {
    http_response_code(500);
    exit('HostShield: ' . e($e->getMessage()));
}

// Health check for monitoring tools: no details.
if ($p === 'ping') {
    header('Content-Type: application/json');
    exit(json_encode(['ok' => true, 'waf' => defined('SHIELD_WAF_LOADED')]));
}

// Web cron, for hosts without a PHP 8 command line: curl -s "https://.../?p=cron&token=..."
if ($p === 'cron') {
    if (!hash_equals(shield_relay_token(), (string)($_GET['token'] ?? ''))) {
        http_response_code(403);
        exit('NO');
    }
    ignore_user_abort(true);
    @set_time_limit(0);
    header('Content-Type: text/plain; charset=utf-8');
    define('SHIELD_WEB_CRON', true);
    define('SHIELD_QUIET', true);
    require __DIR__ . '/cron/worker.php';
    exit('OK ' . date('H:i:s') . "\n");
}

// Mail relay for the CLI worker (see shield_mail_relay).
if ($p === 'relay-mail' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!hash_equals(shield_relay_token(), (string)($_POST['token'] ?? ''))) {
        http_response_code(403);
        exit('NO');
    }
    $ok = shield_mail_send((string)$cfg['notify']['email'], (string)base64_decode((string)($_POST['s'] ?? '')), (string)base64_decode((string)($_POST['b'] ?? '')));
    exit($ok ? 'OK' : 'FAIL');
}

shield_session_start();

$allowed = (array)($cfg['admin_allowed_ips'] ?? []);
if ($allowed && !shield_ip_in_list(shield_client_ip(), $allowed)) {
    http_response_code(403);
    exit('Forbidden');
}

$admin = shield_admin();
if (!$admin) {
    // No admin account (deleted admin.json): the installer's account step, with the same unlock rule.
    require __DIR__ . '/app/install.php';
    exit;
}

// ================= Login =================
if (!shield_logged_in()) {
    $err = '';
    $needCode = !empty($admin['totp']);
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'login') {
        shield_csrf_check();
        if ($wait = shield_login_blocked()) {
            $err = __('Too many attempts. Try again in %d min.', (int)ceil($wait / 60));
        } else {
            $okUser = hash_equals((string)$admin['user'], (string)($_POST['user'] ?? ''));
            $okPass = password_verify((string)($_POST['password'] ?? ''), (string)$admin['hash']);
            $step = 0;
            $code = trim((string)($_POST['code'] ?? ''));
            $okCode = !$needCode;
            if ($needCode && $okUser && $okPass) {
                if (strlen((string)preg_replace('/\D/', '', $code)) === 6 && !str_contains($code, '-')) {
                    $okCode = shield_totp_verify((string)$admin['totp'], $code, $step) && $step > (int)($admin['totp_last'] ?? 0);
                } else {
                    $okCode = shield_recovery_code_use($admin, $code);
                    if ($okCode) {
                        flash(__('You used a recovery code. %d left.', count((array)($admin['recovery'] ?? []))), 'warn');
                    }
                }
            }
            if ($okUser && $okPass && $okCode) {
                if ($step) {
                    $admin['totp_last'] = $step;
                }
                if (password_needs_rehash((string)$admin['hash'], PASSWORD_DEFAULT)) {
                    $admin['hash'] = password_hash((string)$_POST['password'], PASSWORD_DEFAULT);
                }
                shield_login($admin);
                go((string)($_POST['next'] ?? '') !== '' && preg_match('/^p=[a-z_]+(&[a-z_]+=[A-Za-z0-9._-]*)*$/', (string)$_POST['next']) ? (string)$_POST['next'] : '');
            }
            shield_login_failed();
            $err = __('Wrong username, password or code.');
        }
    }
    render_auth(__('Log in'), $err, static function () use ($needCode): void { ?>
        <input type="hidden" name="action" value="login">
        <input type="hidden" name="next" value="<?= e($_SERVER['QUERY_STRING'] ?? '') ?>">
        <label class="field"><span><?= e(__('Username')) ?></span><input name="user" autocomplete="username" required autofocus></label>
        <label class="field"><span><?= e(__('Password')) ?></span><input type="password" name="password" autocomplete="current-password" required></label>
        <?php if ($needCode): ?>
            <label class="field"><span><?= e(__('Authenticator code or recovery code')) ?></span><input name="code" autocomplete="one-time-code" required></label>
        <?php endif; ?>
        <button class="btn primary wide"><?= e(__('Log in')) ?></button>
    <?php });
    exit;
}

// ================= Actions =================
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    shield_csrf_check();
    require __DIR__ . '/app/actions.php';
    go();
}

// ================= Downloads =================
if ($p === 'download') {
    $k = site_key_param();
    $name = (string)($_GET['backup'] ?? '');
    $file = basename((string)($_GET['file'] ?? ''));
    foreach (shield_list_backups($k) as $m) {
        if ($m['name'] !== $name) {
            continue;
        }
        $allowedFiles = array_merge([$m['files']['file']], array_column((array)$m['databases'], 'file'));
        if (in_array($file, $allowedFiles, true) && is_file($m['dir'] . '/' . $file)) {
            shield_log('download', "{$k}/{$name}/{$file} by " . shield_client_ip());
            while (ob_get_level()) {
                ob_end_clean();
            }
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename="' . $k . '_' . $name . '_' . $file . '"');
            header('Content-Length: ' . filesize($m['dir'] . '/' . $file));
            readfile($m['dir'] . '/' . $file);
            exit;
        }
    }
    http_response_code(404);
    exit(e(__('No such file')));
}

// ================= Pages =================
$pages = ['home' => __('Overview'), 'site' => '', 'site_add' => __('Add site'), 'firewall' => __('Firewall'), 'jobs' => __('Tasks'),
    'job' => __('Task'), 'settings' => __('Settings'), 'about' => __('Support')];
if (!isset($pages[$p])) {
    go();
}
$flashes = flash();
$state = shield_state();
$lastCron = (int)($state['last_worker'] ?? 0);
$title = $pages[$p];
ob_start();
require __DIR__ . '/app/pages/' . $p . '.php';
$content = (string)ob_get_clean();
render_layout($p, $title ?: 'HostShield', $content, $flashes);
