<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

function shield_admin(): array
{
    return shield_json_read(shield_path('admin.json'));
}

function shield_admin_save(array $a): void
{
    shield_json_write(shield_path('admin.json'), $a);
    @chmod(shield_path('admin.json'), 0600);
}

function shield_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] ?? '') === '443'
        || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

function shield_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    session_name('SHIELDSESS');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'secure' => shield_https(), 'httponly' => true, 'samesite' => 'Strict',
    ]);
    if (shield_installed()) {
        session_save_path(shield_dir('sessions'));
    }
    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', '7200');
    session_start();
}

function shield_logged_in(): bool
{
    shield_session_start();
    if (empty($_SESSION['uid']) || ($_SESSION['ip'] ?? '') !== shield_client_ip()) {
        return false;
    }
    $limit = 60 * max(5, (int)(shield_config()['session_minutes'] ?? 30));
    if (time() - (int)($_SESSION['seen'] ?? 0) > $limit) {
        $_SESSION = [];
        return false;
    }
    $_SESSION['seen'] = time();
    return true;
}

function shield_login(array &$admin): void
{
    $ip = shield_client_ip();
    $known = (array)($admin['known_ips'] ?? []);
    if ($known && !in_array($ip, $known, true)) {
        require_once __DIR__ . '/notify.php';
        shield_notify('login', __('New login to the dashboard'), __("Login from a new IP address: %s\nBrowser: %s\n\nIf this was not you, change the password and enable 2FA.", $ip, mb_substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 160)));
    }
    $admin['known_ips'] = array_slice(array_values(array_unique(array_merge([$ip], $known))), 0, 20);
    $admin['last_login'] = time();
    $admin['last_ip'] = $ip;
    shield_admin_save($admin);
    session_regenerate_id(true);
    $_SESSION['uid'] = 1;
    $_SESSION['ip'] = $ip;
    $_SESSION['seen'] = time();
    shield_log('auth', 'Login from ' . $ip);
}

function shield_csrf(): string
{
    shield_session_start();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf'];
}

function shield_csrf_check(): void
{
    if (!hash_equals(shield_csrf(), (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit(__('Session expired. Reload the page and try again.'));
    }
}

// --- Brute-force protection for the dashboard login ---

function shield_login_blocked(): int
{
    $f = shield_path('auth/' . preg_replace('/[^0-9a-f]/i', '_', shield_client_ip()) . '.json');
    $s = shield_json_read($f);
    return max(0, (int)($s['until'] ?? 0) - time());
}

function shield_login_failed(): void
{
    $f = shield_dir('auth') . '/' . preg_replace('/[^0-9a-f]/i', '_', shield_client_ip()) . '.json';
    $s = shield_json_read($f);
    if (time() - (int)($s['first'] ?? 0) > 900) {
        $s = ['first' => time(), 'count' => 0];
    }
    $s['count'] = (int)$s['count'] + 1;
    if ($s['count'] >= 5) {
        $s['until'] = time() + 900;
        require_once __DIR__ . '/notify.php';
        shield_notify('login', __('Failed dashboard logins'), __("IP: %s\nBlocked for 15 minutes after 5 failed attempts.", shield_client_ip()));
    }
    shield_json_write($f, $s);
    shield_log('auth', 'Failed login from ' . shield_client_ip());
}

// --- TOTP (Google Authenticator, Authy, Microsoft Authenticator, 1Password...) ---

function shield_base32_encode(string $bin): string
{
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split($bin) as $c) {
        $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $out .= $alpha[bindec(str_pad($chunk, 5, '0'))];
    }
    return $out;
}

function shield_base32_decode(string $b32): string
{
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split(strtoupper((string)preg_replace('/[^A-Za-z2-7]/', '', $b32))) as $c) {
        $bits .= str_pad(decbin((int)strpos($alpha, $c)), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $out .= chr(bindec($byte));
        }
    }
    return $out;
}

function shield_totp(string $secret, int $step): string
{
    $h = hash_hmac('sha1', pack('J', $step), shield_base32_decode($secret), true);
    $o = ord($h[19]) & 0xF;
    $n = ((ord($h[$o]) & 0x7F) << 24) | (ord($h[$o + 1]) << 16) | (ord($h[$o + 2]) << 8) | ord($h[$o + 3]);
    return str_pad((string)($n % 1000000), 6, '0', STR_PAD_LEFT);
}

function shield_totp_verify(string $secret, string $code, int &$usedStep = 0): bool
{
    $code = (string)preg_replace('/\D/', '', $code);
    if (strlen($code) !== 6) {
        return false;
    }
    $t = intdiv(time(), 30);
    for ($i = -1; $i <= 1; $i++) {
        if (hash_equals(shield_totp($secret, $t + $i), $code)) {
            $usedStep = $t + $i;
            return true;
        }
    }
    return false;
}

/** Ten one-time recovery codes; only their hashes are stored. */
function shield_recovery_codes_new(array &$admin): array
{
    $codes = [];
    for ($i = 0; $i < 10; $i++) {
        $raw = strtoupper(bin2hex(random_bytes(5)));
        $codes[] = substr($raw, 0, 5) . '-' . substr($raw, 5);
    }
    $admin['recovery'] = array_map(static fn($c) => password_hash($c, PASSWORD_DEFAULT), $codes);
    return $codes;
}

function shield_recovery_code_use(array &$admin, string $code): bool
{
    $code = strtoupper(trim($code));
    foreach ((array)($admin['recovery'] ?? []) as $i => $hash) {
        if (password_verify($code, (string)$hash)) {
            unset($admin['recovery'][$i]);
            $admin['recovery'] = array_values($admin['recovery']);
            return true;
        }
    }
    return false;
}
