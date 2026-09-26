<?php
declare(strict_types=1);

const SHIELD_VERSION = '2.1.0';
const SHIELD_REPO = 'borko1912/HostShield';
const SHIELD_FUNDING = ['GitHub Sponsors' => 'https://github.com/sponsors/borko1912'];

require_once dirname(__DIR__) . '/waf/engine.php';
require_once __DIR__ . '/i18n.php';

// ---------------------------------------------------------------------------
// Configuration
//
// config.php (next to index.php) only says where the data folder is.
// Everything else lives in <data_dir>/settings.php and is edited from the dashboard.
// A v1 config.php that holds the full configuration is imported on first run.
// ---------------------------------------------------------------------------

function shield_root(): string
{
    return dirname(__DIR__);
}

function shield_config_file(): string
{
    return (string)(getenv('SHIELD_CONFIG') ?: shield_root() . '/config.php');
}

function shield_installed(): bool
{
    return is_file(shield_config_file());
}

function shield_boot_config(): array
{
    $f = shield_config_file();
    return is_file($f) ? (array)(require $f) : [];
}

function shield_defaults(): array
{
    // No non-empty lists here: settings are merged with array_replace_recursive.
    return [
        'language' => 'auto',
        'timezone' => date_default_timezone_get() ?: 'UTC',
        'dashboard_url' => '',
        'admin_allowed_ips' => [],
        'session_minutes' => 30,
        'db' => ['host' => 'localhost', 'port' => 3306, 'user' => '', 'pass' => ''],
        'backup' => [
            'enabled' => true,
            'hour' => 3,
            'keep_daily' => 7,
            'keep_weekly' => 4,
            'keep_monthly' => 3,
            'keep_pre_restore' => 3,
            'max_file_mb' => 500,
            'offsite' => [
                'type' => 'none', // none | ftp | s3
                'ftp' => ['host' => '', 'port' => 21, 'user' => '', 'pass' => '', 'dir' => '/shield-backups', 'ssl' => true],
                's3' => ['endpoint' => '', 'region' => 'auto', 'bucket' => '', 'key' => '', 'secret' => '', 'prefix' => 'shield/', 'path_style' => true],
            ],
        ],
        'monitor' => [
            'integrity_minutes' => 60,
            'uptime_minutes' => 5,
            'audit_hours' => 24,
            'ssl_warn_days' => 14,
            'auto_quarantine' => false,
        ],
        'waf' => [
            'mode' => 'log', // log | block
            'rate_limit_per_min' => 600,
            'login_limit' => 10,
            'login_window' => 600,
            'strikes_to_ban' => 3,
            'strike_window' => 600,
            'ban_minutes' => 60,
            'block_exec_in_uploads' => true,
            'wp_block_xmlrpc' => false,
            'wp_block_user_enum' => true,
            'allow' => [],
            'block' => [],
            'trusted_proxies' => [],
        ],
        'notify' => [
            'email' => '',
            'email_enabled' => true,  // master switch for email alerts (keeps the address)
            'ban_digest' => 'hourly', // off | hourly | 6h | daily
            'max_per_day' => 0,       // cap for non-critical alerts, 0 = no limit
            'mail_from' => '',
            'transport' => 'mail', // mail | smtp
            'smtp' => ['host' => '', 'port' => 587, 'secure' => 'tls', 'user' => '', 'pass' => ''],
            'telegram' => ['token' => '', 'chat_id' => ''],
            'webhook' => ['url' => '', 'format' => 'discord'], // discord | slack | generic
            'events' => [
                'backup_failed' => true, 'malware' => true, 'changes' => true, 'down' => true, 'ban' => true,
                'login' => true, 'restore' => true, 'audit' => true, 'ssl' => true, 'update' => true,
            ],
        ],
        'banner' => ['enabled' => false, 'text' => 'Protected by HostShield', 'seconds' => 4, 'show' => 'session'],
        'updates' => ['check' => true],
        'sites' => [],
    ];
}

function shield_site_defaults(): array
{
    return [
        'title' => '',
        'url' => '',
        'hosts' => [],
        'path' => '',
        'platform' => 'php',
        'db' => [],            // own credentials (host, port, user, pass); empty = global
        'databases' => [],
        'db_patterns' => [],
        'exclude' => ['error_log', '*/error_log', '*.log', 'tmp/*', 'cache/*'],
        'upload_dirs' => [],
        'waf_mode' => null,    // null = global | log | block | off
        'waf_skip_paths' => [],
        'waf_exceptions' => [],
        'waf_disabled_rules' => [],
        'lockdown' => false,
        'banner' => true,
        'backup' => true,
        'scan_ignore' => [],   // rel path => sha1 of a file marked as a false positive
    ];
}

/** Brings v1 keys to the v2 layout and fills per-site defaults. */
function shield_normalize(array $c): array
{
    if (isset($c['alert_email']) && empty($c['notify']['email'])) {
        $c['notify']['email'] = (string)$c['alert_email'];
    }
    if (isset($c['mail_from']) && empty($c['notify']['mail_from'])) {
        $c['notify']['mail_from'] = (string)$c['mail_from'];
    }
    if (isset($c['backup']['keep'])) {
        $c['backup']['keep_daily'] = (int)$c['backup']['keep'];
    }
    $off = (array)($c['backup']['offsite'] ?? []);
    if (($off['type'] ?? '') === 'ftp' && isset($off['host'])) { // v1 flat FTP settings
        $c['backup']['offsite']['ftp'] = array_intersect_key($off, array_flip(['host', 'port', 'user', 'pass', 'dir', 'ssl']));
    }
    unset($c['alert_email'], $c['mail_from'], $c['backup']['keep'], $c['setup_key']);
    foreach (['host', 'port', 'user', 'pass', 'dir', 'ssl'] as $k) {
        unset($c['backup']['offsite'][$k]);
    }
    foreach (['allow_ips' => 'allow', 'block_ips' => 'block'] as $old => $new) {
        foreach ((array)($c['waf'][$old] ?? []) as $ip) {
            $c['waf'][$new][] = ['ip' => (string)$ip, 'note' => '', 't' => 0];
        }
        unset($c['waf'][$old]);
    }
    unset($c['waf']['alert_on_ban']);
    $sites = [];
    foreach ((array)($c['sites'] ?? []) as $k => $s) {
        $s = array_replace(shield_site_defaults(), (array)$s);
        $s['title'] = (string)($s['title'] ?: $k);
        $s['path'] = rtrim(str_replace('\\', '/', (string)$s['path']), '/');
        $sites[(string)$k] = $s;
    }
    $c['sites'] = $sites;
    return $c;
}

function shield_config(bool $reload = false): array
{
    static $cfg = null;
    if ($cfg === null || $reload) {
        $boot = shield_boot_config();
        if (!$boot) {
            throw new RuntimeException('HostShield is not installed yet.');
        }
        $data = rtrim(str_replace('\\', '/', (string)($boot['data_dir'] ?? '')), '/');
        if ($data === '') {
            throw new RuntimeException('config.php has no data_dir.');
        }
        $sf = $data . '/settings.php';
        $settings = is_file($sf) ? (array)(include $sf) : array_diff_key($boot, ['data_dir' => 1]);
        $cfg = shield_normalize(array_replace_recursive(shield_defaults(), $settings));
        $cfg['data_dir'] = $data;
        $cfg['_legacy'] = !is_file($sf);
        @date_default_timezone_set((string)$cfg['timezone']);
    }
    return $cfg;
}

/** Everything the dashboard can edit, without runtime-only keys. */
function shield_settings(): array
{
    return array_diff_key(shield_config(), ['data_dir' => 1, '_legacy' => 1]);
}

/** Saves settings to <data_dir>/settings.php (a PHP file: never readable over HTTP even if exposed). */
function shield_settings_save(array $settings): void
{
    $settings = shield_normalize(array_diff_key($settings, ['data_dir' => 1, '_legacy' => 1]));
    $file = shield_path('settings.php');
    shield_php_write($file, $settings, 'HostShield settings. Managed from the dashboard.');
    shield_config(true);
}

/** Writes a PHP file that returns $data, atomically, and drops it from opcache. */
function shield_php_write(string $file, array $data, string $comment = ''): void
{
    $dir = dirname($file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $code = "<?php\n" . ($comment !== '' ? '// ' . $comment . "\n" : '') . 'return ' . var_export($data, true) . ";\n";
    $tmp = $file . '.tmp' . getmypid();
    if (file_put_contents($tmp, $code, LOCK_EX) === false) {
        throw new RuntimeException('Cannot write ' . $file);
    }
    @chmod($tmp, 0600);
    rename($tmp, $file);
    if (function_exists('opcache_invalidate')) {
        @opcache_invalidate($file, true);
    }
}

/** One-time import of v1 configuration (full config.php + waf/lists.json) into settings.php. */
function shield_migrate(): void
{
    $cfg = shield_config();
    $lists = shield_path('waf/lists.json');
    if (!$cfg['_legacy'] && !is_file($lists)) {
        return;
    }
    $s = shield_settings();
    if (is_file($lists)) {
        $l = shield_json_read($lists);
        foreach (['allow', 'block'] as $w) {
            foreach ((array)($l[$w] ?? []) as $x) {
                if (!shield_ip_in_list((string)($x['ip'] ?? ''), (array)$s['waf'][$w])) {
                    $s['waf'][$w][] = ['ip' => (string)$x['ip'], 'note' => (string)($x['note'] ?? ''), 't' => (int)($x['t'] ?? 0)];
                }
            }
        }
    }
    foreach ($s['sites'] as $k => $site) {
        if (($site['platform'] ?? 'php') === 'php' && is_dir($site['path'])) {
            require_once __DIR__ . '/detect.php';
            $s['sites'][$k]['platform'] = shield_detect_platform($site['path']);
        }
    }
    shield_settings_save($s);
    if (is_file($lists)) {
        @rename($lists, $lists . '.imported');
    }
    shield_log('setup', 'Imported v1 configuration into settings.php');
}

// ---------------------------------------------------------------------------
// Paths and storage
// ---------------------------------------------------------------------------

function shield_path(string $rel = ''): string
{
    return shield_config()['data_dir'] . ($rel !== '' ? '/' . ltrim($rel, '/') : '');
}

function shield_dir(string $rel): string
{
    $d = shield_path($rel);
    if (!is_dir($d) && !@mkdir($d, 0700, true) && !is_dir($d)) {
        throw new RuntimeException('Cannot create folder: ' . $d);
    }
    return $d;
}

function shield_sites(): array
{
    return (array)(shield_config()['sites'] ?? []);
}

function shield_site(string $key): array
{
    $sites = shield_sites();
    if (!isset($sites[$key])) {
        throw new RuntimeException('Unknown site: ' . $key);
    }
    $s = (array)$sites[$key];
    $s['key'] = $key;
    return $s;
}

function shield_json_read(string $file, array $default = []): array
{
    if (!is_file($file)) {
        return $default;
    }
    $d = json_decode((string)@file_get_contents($file), true);
    return is_array($d) ? $d : $default;
}

function shield_json_write(string $file, array $data): void
{
    $dir = dirname($file);
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $tmp = $file . '.tmp' . getmypid();
    file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
    rename($tmp, $file);
}

function shield_state(): array
{
    return shield_json_read(shield_path('state.json'));
}

/** Read-modify-write of state.json under a lock. */
function shield_state_update(callable $fn): array
{
    $file = shield_path('state.json');
    $h = fopen(shield_dir('') . '/state.lock', 'c');
    flock($h, LOCK_EX);
    try {
        $st = $fn(shield_json_read($file));
        shield_json_write($file, $st);
    } finally {
        flock($h, LOCK_UN);
        fclose($h);
    }
    return $st;
}

function shield_log(string $channel, string $message, array $ctx = []): void
{
    $line = date('Y-m-d H:i:s') . ' [' . $channel . '] ' . $message . ($ctx ? ' ' . json_encode($ctx, JSON_UNESCAPED_UNICODE) : '');
    @file_put_contents(shield_dir('logs') . '/shield-' . date('Y-m-d') . '.log', $line . "\n", FILE_APPEND | LOCK_EX);
    if (PHP_SAPI === 'cli' && !defined('SHIELD_QUIET')) {
        fwrite(STDOUT, $line . "\n");
    }
}

/** Protects the data folder in case it ends up inside a web root. */
function shield_protect_data_dir(): void
{
    $d = shield_dir('');
    if (!is_file($d . '/.htaccess')) {
        @file_put_contents($d . '/.htaccess', "Require all denied\nDeny from all\n");
    }
    if (!is_file($d . '/index.html')) {
        @file_put_contents($d . '/index.html', '');
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function shield_human_size(float $bytes): string
{
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($bytes >= 1024 && $i < count($u) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return round($bytes, $i ? 1 : 0) . ' ' . $u[$i];
}

function shield_ago(int $ts): string
{
    if ($ts <= 0) {
        return __('never');
    }
    $d = time() - $ts;
    if ($d < 60) {
        return __('%d sec ago', max(0, $d));
    }
    if ($d < 3600) {
        return __('%d min ago', intdiv($d, 60));
    }
    if ($d < 86400) {
        return __('%d h ago', intdiv($d, 3600));
    }
    return __('%d days ago', intdiv($d, 86400));
}

function shield_rrmdir(string $dir): void
{
    if (is_link($dir) || is_file($dir)) {
        @unlink($dir);
        return;
    }
    if (!is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        $f->isDir() && !$f->isLink() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
    }
    @rmdir($dir);
}

/** Does a relative path match one of the glob exclusions? */
function shield_excluded(string $rel, array $patterns): bool
{
    foreach ($patterns as $p) {
        $p = trim((string)$p, '/');
        if ($p === '') {
            continue;
        }
        if (fnmatch($p, $rel) || str_starts_with($rel, $p . '/')) {
            return true;
        }
    }
    return false;
}

/** Walks a site's files (without exclusions and symlinks). Yields relativePath => SplFileInfo. */
function shield_walk(array $site, array $extraExclude = []): Generator
{
    $root = rtrim(str_replace('\\', '/', (string)$site['path']), '/');
    $exclude = array_merge((array)($site['exclude'] ?? []), $extraExclude, shield_auto_excludes($root));
    $dirIt = new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS);
    $filter = new RecursiveCallbackFilterIterator($dirIt, static function (SplFileInfo $f) use ($root, $exclude): bool {
        if ($f->isLink()) {
            return false;
        }
        $rel = ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($root))), '/');
        return !shield_excluded($rel, $exclude);
    });
    $it = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD);
    foreach ($it as $f) {
        $rel = ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($root))), '/');
        yield $rel => $f;
    }
}

/** Folders that never belong to a site's backup: Shield itself, its data, sites nested inside. */
function shield_auto_excludes(string $root): array
{
    $out = [];
    $candidates = [shield_root(), shield_config()['data_dir']];
    foreach (shield_sites() as $s) {
        $candidates[] = (string)$s['path'];
    }
    $r = rtrim(str_replace('\\', '/', $root), '/');
    foreach ($candidates as $c) {
        $c = rtrim(str_replace('\\', '/', (string)(realpath($c) ?: $c)), '/');
        if ($c !== $r && str_starts_with($c, $r . '/')) {
            $out[] = substr($c, strlen($r) + 1);
        }
    }
    return $out;
}

/**
 * Secret that marks HostShield's own requests to the protected sites (uptime
 * monitor, security audit, mail relay). The firewall still applies its rules to
 * them, but never counts strikes, bans, rate-limits or logs them as attacks —
 * otherwise the audit's probes for /.env, /.git … got the server's own IP
 * banned and every uptime check afterwards failed with 403.
 * Deliberately a secret and not "trust the server IP": on shared hosting other
 * tenants send requests from that same IP.
 */
function shield_internal_key(): string
{
    $f = shield_path('waf/internal.key');
    $k = is_file($f) ? trim((string)@file_get_contents($f)) : '';
    if (strlen($k) < 32) {
        shield_dir('waf');
        $k = bin2hex(random_bytes(24));
        file_put_contents($f, $k, LOCK_EX);
        @chmod($f, 0600);
    }
    return $k;
}

/** The internal key when $url points to one of our own sites or the dashboard, else null (never leak it elsewhere). */
function shield_internal_key_for(string $url): ?string
{
    $host = strtolower((string)parse_url($url, PHP_URL_HOST));
    if ($host === '') {
        return null;
    }
    try {
        $own = [];
        foreach (shield_sites() as $s) {
            foreach ((array)($s['hosts'] ?? []) as $h) {
                $own[] = strtolower((string)$h);
            }
            $own[] = strtolower((string)parse_url((string)($s['url'] ?? ''), PHP_URL_HOST));
        }
        $own[] = strtolower((string)parse_url(shield_dashboard_url(), PHP_URL_HOST));
        return in_array($host, array_filter($own), true) ? shield_internal_key() : null;
    } catch (Throwable $e) {
        return null;
    }
}

/** Resolves a Location header against the URL it came from. */
function shield_url_resolve(string $base, string $loc): string
{
    if (preg_match('#^https?://#i', $loc)) {
        return $loc;
    }
    $p = parse_url($base);
    $scheme = (string)($p['scheme'] ?? 'https');
    if (str_starts_with($loc, '//')) {
        return $scheme . ':' . $loc;
    }
    $origin = $scheme . '://' . ($p['host'] ?? '') . (isset($p['port']) ? ':' . $p['port'] : '');
    if (str_starts_with($loc, '/')) {
        return $origin . $loc;
    }
    $path = (string)($p['path'] ?? '/');
    $dir = substr($path, 0, (int)strrpos($path, '/') + 1);
    return $origin . ($dir !== '' ? $dir : '/') . $loc;
}

/**
 * Small HTTP client.
 * Options: method, headers (list), body, timeout, follow, range, sink (file path), infile (file path to upload), nobody.
 * Returns ['code', 'headers' (lowercase name => value), 'body', 'error', 'ms', 'url'].
 *
 * Requests to our own sites carry the internal key; their redirects are then
 * followed by hand so the key is never sent to another host (curl repeats
 * custom headers on a cross-host redirect).
 */
function shield_http(string $url, array $o = []): array
{
    $key = shield_internal_key_for($url);
    if ($key === null) {
        return shield_http_raw($url, $o);
    }
    $follow = (bool)($o['follow'] ?? true);
    $plain = $o;
    $o['follow'] = false;
    $o['headers'] = array_merge((array)($o['headers'] ?? []), ['X-HostShield-Internal: ' . $key]);
    for ($i = 0; ; $i++) {
        $r = shield_http_raw($url, $o);
        $loc = (string)($r['headers']['location'] ?? '');
        if (!$follow || $i >= 5 || $r['code'] < 300 || $r['code'] >= 400 || $loc === '') {
            return $r;
        }
        $url = shield_url_resolve($url, $loc);
        if (shield_internal_key_for($url) === null) {
            return shield_http_raw($url, $plain); // left our sites: continue without the key
        }
    }
}

/** shield_http() without the internal key handling. */
function shield_http_raw(string $url, array $o = []): array
{
    if (!function_exists('curl_init')) {
        return ['code' => 0, 'headers' => [], 'body' => '', 'error' => 'PHP curl extension missing', 'ms' => 0, 'url' => $url];
    }
    $headers = [];
    $ch = curl_init($url);
    $opts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => (bool)($o['follow'] ?? true),
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => (int)($o['timeout'] ?? 20),
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_USERAGENT => (string)($o['ua'] ?? 'HostShield/' . SHIELD_VERSION),
        CURLOPT_HTTPHEADER => (array)($o['headers'] ?? []),
        CURLOPT_CUSTOMREQUEST => (string)($o['method'] ?? 'GET'),
        CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headers): int {
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $headers[strtolower(trim($k))] = trim($v);
            } elseif (str_starts_with($line, 'HTTP/')) {
                $headers = []; // new response after a redirect
            }
            return strlen($line);
        },
    ];
    if (isset($o['range'])) {
        $opts[CURLOPT_RANGE] = (string)$o['range'];
    }
    if (!empty($o['nobody'])) {
        $opts[CURLOPT_NOBODY] = true;
    }
    if (isset($o['body'])) {
        $opts[CURLOPT_POSTFIELDS] = $o['body'];
    }
    $in = null;
    if (isset($o['infile'])) {
        $in = fopen((string)$o['infile'], 'rb');
        $opts[CURLOPT_UPLOAD] = true;
        $opts[CURLOPT_INFILE] = $in;
        $opts[CURLOPT_INFILESIZE] = filesize((string)$o['infile']);
        $opts[CURLOPT_TIMEOUT] = (int)($o['timeout'] ?? 3600);
    }
    $out = null;
    if (isset($o['sink'])) {
        $out = fopen((string)$o['sink'], 'wb');
        $opts[CURLOPT_FILE] = $out;
        unset($opts[CURLOPT_RETURNTRANSFER]);
        $opts[CURLOPT_TIMEOUT] = (int)($o['timeout'] ?? 3600);
    }
    curl_setopt_array($ch, $opts);
    $t = microtime(true);
    $body = curl_exec($ch);
    $res = [
        'code' => (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
        'headers' => $headers,
        'body' => is_string($body) ? $body : '',
        'error' => curl_error($ch),
        'ms' => (int)round((microtime(true) - $t) * 1000),
        'url' => (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL),
    ];
    curl_close($ch);
    $in && fclose($in);
    $out && fclose($out);
    return $res;
}

/** Days until the TLS certificate of a host expires (null if it cannot be read). */
function shield_ssl_days_left(string $host, int $port = 443): ?array
{
    $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $host]]);
    $s = @stream_socket_client('ssl://' . $host . ':' . $port, $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
    if (!$s) {
        return null;
    }
    $params = stream_context_get_params($s);
    fclose($s);
    $cert = $params['options']['ssl']['peer_certificate'] ?? null;
    $info = $cert ? openssl_x509_parse($cert) : false;
    if (!$info) {
        return null;
    }
    $to = (int)$info['validTo_time_t'];
    return ['expires' => $to, 'days' => (int)floor(($to - time()) / 86400), 'issuer' => (string)($info['issuer']['O'] ?? $info['issuer']['CN'] ?? '')];
}

function shield_client_ip(): string
{
    return (string)($_SERVER['REMOTE_ADDR'] ?? '');
}

function shield_random_key(int $bytes = 24): string
{
    return bin2hex(random_bytes($bytes));
}

/** Secret used by the CLI worker to talk to the dashboard (mail relay, web cron). */
function shield_relay_token(): string
{
    $f = shield_dir('') . '/relay.token';
    if (!is_file($f)) {
        file_put_contents($f, shield_random_key(), LOCK_EX);
        @chmod($f, 0600);
    }
    return trim((string)file_get_contents($f));
}

function shield_dashboard_url(): string
{
    $u = rtrim((string)(shield_config()['dashboard_url'] ?? ''), '/');
    if ($u === '' && PHP_SAPI !== 'cli' && !empty($_SERVER['HTTP_HOST'])) {
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] ?? '') === '443';
        $u = ($https ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . rtrim(dirname((string)$_SERVER['SCRIPT_NAME']), '/\\');
    }
    return $u;
}
