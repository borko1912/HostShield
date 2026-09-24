<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

// Switching the firewall on/off for a site by adding auto_prepend_file to its PHP settings.
// PHP-FPM / CGI / LiteSpeed read a per-folder ini file (.user.ini, or php.ini on some hosts);
// Apache mod_php reads php_value from .htaccess.

function shield_waf_file(): string
{
    return str_replace('\\', '/', shield_root()) . '/waf/firewall.php';
}

function shield_waf_prepend_line(): string
{
    return 'auto_prepend_file = "' . shield_waf_file() . '"';
}

/** 'ini' (user ini file) or 'htaccess' (mod_php). */
function shield_waf_method(): string
{
    return PHP_SAPI === 'apache2handler' ? 'htaccess' : 'ini';
}

function shield_site_ini_path(array $s): string
{
    $name = shield_waf_method() === 'htaccess' ? '.htaccess' : (ini_get('user_ini.filename') ?: '.user.ini');
    return rtrim((string)$s['path'], '/') . '/' . $name;
}

/** Web root of a site (Laravel serves from public/). */
function shield_site_docroot(array $s): string
{
    $p = rtrim((string)$s['path'], '/');
    return ($s['platform'] ?? '') === 'laravel' && is_dir($p . '/public') ? $p . '/public' : $p;
}

/** 'on' | 'off' | 'other' (a different auto_prepend_file is set) */
function shield_site_waf_state(array $s): string
{
    $f = shield_site_ini_path(['path' => shield_site_docroot($s)]);
    $c = is_file($f) ? (string)file_get_contents($f) : '';
    if (!preg_match('/^\s*(?:php_value\s+)?auto_prepend_file\s*=?\s*(.+)$/mi', $c, $m)) {
        return 'off';
    }
    return str_contains($m[1], '/waf/firewall.php') ? 'on' : 'other';
}

function shield_site_waf_set(array $s, bool $on): string
{
    $f = shield_site_ini_path(['path' => shield_site_docroot($s)]);
    $c = is_file($f) ? (string)file_get_contents($f) : '';
    $state = shield_site_waf_state($s);
    if ($state === 'other') {
        return __('%s already sets a different auto_prepend_file — left unchanged.', basename($f));
    }
    if (($state === 'on') === $on) {
        return $on ? __('The firewall is already on.') : __('The firewall is already off.');
    }
    if (is_file($f)) {
        @copy($f, shield_dir('ini-backups') . '/' . basename(dirname($f)) . '-' . basename($f) . '-' . date('Ymd-His'));
    }
    $nl = str_contains($c, "\r\n") ? "\r\n" : "\n";
    $isHt = basename($f) === '.htaccess';
    if ($on) {
        $line = $isHt ? 'php_value auto_prepend_file "' . shield_waf_file() . '"' : shield_waf_prepend_line();
        $block = '# HostShield firewall (fail-open: if it errors, the site keeps working)' . $nl . $line . $nl;
        if (!$isHt) {
            $block = '; HostShield firewall (fail-open: if it errors, the site keeps working)' . $nl . $line . $nl;
        }
        $c = $isHt ? $block . $nl . $c : rtrim($c) . ($c !== '' ? $nl . $nl : '') . $block;
    } else {
        $c = (string)preg_replace('/^\s*[;#]\s*(HostShield|Ivanoff Shield).*\R?|^\s*(php_value\s+)?auto_prepend_file\s*=?.*\/waf\/firewall\.php.*\R?/mi', '', $c);
    }
    if (@file_put_contents($f, $c, LOCK_EX) === false) {
        return __('Cannot write %s', $f);
    }
    shield_log('waf', ($on ? 'Enabled' : 'Disabled') . ' firewall for ' . $s['path'] . ' by ' . shield_client_ip());
    $ttl = (int)ini_get('user_ini.cache_ttl');
    return ($on ? __('Firewall enabled.') : __('Firewall disabled.'))
        . (!$isHt && $ttl > 0 ? ' ' . __('It takes effect within %d min.', max(1, intdiv($ttl, 60))) : '');
}

/** Adds a false-positive exception for a rule on a path. */
function shield_waf_add_exception(string $siteKey, string $rule, string $path): void
{
    $s = shield_settings();
    $path = strtolower('/' . ltrim($path, '/'));
    foreach ((array)$s['sites'][$siteKey]['waf_exceptions'] as $ex) {
        if (($ex['rule'] ?? '') === $rule && ($ex['path'] ?? '') === $path) {
            return;
        }
    }
    $s['sites'][$siteKey]['waf_exceptions'][] = ['rule' => $rule, 'path' => $path, 't' => time()];
    shield_settings_save($s);
    shield_log('waf', "Exception {$siteKey}: {$rule} on {$path}");
}

/** Last N firewall events (today and the previous days), newest first. */
function shield_waf_events(int $limit = 300, ?string $ip = null, ?string $site = null, int $days = 2): array
{
    $out = [];
    for ($d = 0; $d < $days; $d++) {
        $f = shield_path('logs/waf-' . date('Y-m-d', time() - $d * 86400) . '.jsonl');
        if (!is_file($f)) {
            continue;
        }
        $size = filesize($f);
        $h = fopen($f, 'rb');
        if ($size > 8388608) {
            fseek($h, -8388608, SEEK_END);
            fgets($h);
        }
        $lines = [];
        while (($l = fgets($h)) !== false) {
            $lines[] = $l;
        }
        fclose($h);
        foreach (array_reverse($lines) as $l) {
            $ev = json_decode($l, true);
            if (!$ev || ($ip && $ev['ip'] !== $ip) || ($site && $ev['site'] !== $site)) {
                continue;
            }
            $out[] = $ev;
            if (count($out) >= $limit) {
                return $out;
            }
        }
    }
    return $out;
}

/** Events per day for the last N days: [date => ['logged' => n, 'blocked' => n]]. Cached per finished day. */
function shield_waf_daily(int $days = 14): array
{
    $cacheFile = shield_path('cache/waf-daily.json');
    $cache = shield_json_read($cacheFile);
    $out = [];
    $changed = false;
    for ($d = $days - 1; $d >= 0; $d--) {
        $date = date('Y-m-d', time() - $d * 86400);
        if ($d > 0 && isset($cache[$date])) {
            $out[$date] = $cache[$date];
            continue;
        }
        $row = ['logged' => 0, 'blocked' => 0];
        $f = shield_path('logs/waf-' . $date . '.jsonl');
        if (is_file($f)) {
            $h = fopen($f, 'rb');
            while (($l = fgets($h)) !== false) {
                $row[str_contains($l, '"action":"logged"') ? 'logged' : 'blocked']++;
            }
            fclose($h);
        }
        $out[$date] = $row;
        if ($d > 0) {
            $cache[$date] = $row;
            $changed = true;
        }
    }
    if ($changed) {
        $cache = array_slice($cache, -60, null, true);
        shield_json_write($cacheFile, $cache);
    }
    return $out;
}

function shield_waf_bans(): array
{
    $out = [];
    foreach ((array)glob(shield_path('waf/bans') . '/*.json') as $f) {
        $b = shield_json_read((string)$f);
        if ((int)($b['until'] ?? 0) > time()) {
            $b['file'] = basename((string)$f);
            $out[] = $b;
        }
    }
    usort($out, static fn($a, $b) => $b['since'] <=> $a['since']);
    return $out;
}

function shield_valid_ip_or_cidr(string $v): bool
{
    if (str_contains($v, '/')) {
        [$ip, $bits] = explode('/', $v, 2);
        $max = str_contains($ip, ':') ? 128 : 32;
        return (bool)filter_var($ip, FILTER_VALIDATE_IP) && ctype_digit($bits) && (int)$bits >= 8 && (int)$bits <= $max;
    }
    return (bool)filter_var($v, FILTER_VALIDATE_IP);
}
