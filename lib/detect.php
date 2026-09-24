<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

// Site discovery and platform detection.
// Finds web roots in the hosting account, recognizes the application and reads its
// database credentials from its own config file (parsed as text, never executed).

const SHIELD_PLATFORMS = [
    'wordpress' => 'WordPress',
    'laravel' => 'Laravel',
    'joomla' => 'Joomla',
    'drupal' => 'Drupal',
    'prestashop' => 'PrestaShop',
    'opencart' => 'OpenCart',
    'magento' => 'Magento',
    'php' => 'PHP',
    'static' => 'Static HTML',
];

function shield_detect_platform(string $path): string
{
    $p = rtrim($path, '/');
    return match (true) {
        is_file($p . '/wp-config.php') || is_file(dirname($p) . '/wp-config.php') && is_dir($p . '/wp-includes') => 'wordpress',
        is_file($p . '/artisan') || (is_file(dirname($p) . '/artisan') && basename($p) === 'public') => 'laravel',
        is_file($p . '/configuration.php') && is_dir($p . '/administrator') => 'joomla',
        is_file($p . '/sites/default/settings.php') || is_file($p . '/web/sites/default/settings.php') => 'drupal',
        is_file($p . '/app/config/parameters.php') || is_file($p . '/config/settings.inc.php') => 'prestashop',
        is_file($p . '/config.php') && is_dir($p . '/catalog') && is_dir($p . '/system') => 'opencart',
        is_file($p . '/app/etc/env.php') => 'magento',
        (bool)glob($p . '/*.php') => 'php',
        default => 'static',
    };
}

/** Default upload folders per platform (PHP must never run there). */
function shield_platform_upload_dirs(string $platform, string $path): array
{
    $dirs = match ($platform) {
        'wordpress' => ['wp-content/uploads'],
        'laravel' => ['storage/app/public', 'public/storage', 'storage'],
        'joomla' => ['images', 'media/uploads'],
        'drupal' => ['sites/default/files'],
        'prestashop' => ['img', 'upload', 'download'],
        'opencart' => ['image', 'system/storage/upload'],
        'magento' => ['pub/media'],
        default => ['uploads', 'upload', 'files', 'images'],
    };
    // Platform folders are kept even before the first upload creates them; the generic guesses only if they exist.
    return $platform === 'php' || $platform === 'static'
        ? array_values(array_filter($dirs, static fn($d) => is_dir(rtrim($path, '/') . '/' . $d)))
        : $dirs;
}

/** Default backup exclusions per platform (caches and logs). */
function shield_platform_excludes(string $platform): array
{
    $base = ['error_log', '*/error_log', '*.log'];
    return array_merge($base, match ($platform) {
        'wordpress' => ['wp-content/cache/*', 'wp-content/upgrade/*', 'wp-content/*backup*/*', 'wp-content/updraft/*', 'wp-content/ai1wm-backups/*'],
        'laravel' => ['storage/framework/cache/*', 'storage/framework/sessions/*', 'storage/framework/views/*', 'storage/logs/*', 'node_modules/*'],
        'joomla' => ['cache/*', 'administrator/cache/*', 'tmp/*'],
        'drupal' => ['sites/default/files/php/*', 'sites/default/files/css/*', 'sites/default/files/js/*'],
        'prestashop' => ['var/cache/*', 'cache/smarty/*'],
        'opencart' => ['system/storage/cache/*', 'system/storage/logs/*'],
        'magento' => ['var/cache/*', 'var/page_cache/*', 'generated/*', 'pub/static/*'],
        default => ['tmp/*', 'cache/*'],
    });
}

/**
 * Database credentials from the application's config.
 * Returns ['host', 'port', 'user', 'pass', 'name'] or [] if not found.
 */
function shield_detect_db(string $path, string $platform): array
{
    $p = rtrim($path, '/');
    $read = static fn(string $f): string => is_file($f) && filesize($f) < 2 * 1048576 ? (string)file_get_contents($f) : '';
    $str = '(?:\'((?:[^\'\\\\]|\\\\.)*)\'|"((?:[^"\\\\]|\\\\.)*)")';
    $val = static fn(array $m, int $i): string => stripcslashes($m[$i] !== '' ? $m[$i] : ($m[$i + 1] ?? ''));
    $define = static function (string $src, string $name) use ($str, $val): ?string {
        return preg_match('/define\s*\(\s*[\'"]' . preg_quote($name, '/') . '[\'"]\s*,\s*' . $str . '/', $src, $m) ? $val($m, 1) : null;
    };
    $arrayKey = static function (string $src, string $key) use ($str, $val): ?string {
        return preg_match('/[\'"]' . preg_quote($key, '/') . '[\'"]\s*=>\s*' . $str . '/', $src, $m) ? $val($m, 1) : null;
    };
    $out = [];
    switch ($platform) {
        case 'wordpress':
            $src = $read($p . '/wp-config.php') ?: $read(dirname($p) . '/wp-config.php');
            $out = ['name' => $define($src, 'DB_NAME'), 'user' => $define($src, 'DB_USER'), 'pass' => $define($src, 'DB_PASSWORD'), 'host' => $define($src, 'DB_HOST')];
            break;
        case 'laravel':
            $env = shield_parse_env($read($p . '/.env') ?: $read(dirname($p) . '/.env'));
            $out = ['name' => $env['DB_DATABASE'] ?? null, 'user' => $env['DB_USERNAME'] ?? null, 'pass' => $env['DB_PASSWORD'] ?? null,
                'host' => $env['DB_HOST'] ?? null, 'port' => $env['DB_PORT'] ?? null];
            break;
        case 'joomla':
            $src = $read($p . '/configuration.php');
            $prop = static fn(string $n): ?string => preg_match('/public\s+\$' . $n . '\s*=\s*' . $str . '/', $src, $m) ? $val($m, 1) : null;
            $out = ['name' => $prop('db'), 'user' => $prop('user'), 'pass' => $prop('password'), 'host' => $prop('host')];
            break;
        case 'drupal':
            $src = $read($p . '/sites/default/settings.php') ?: $read($p . '/web/sites/default/settings.php');
            if (preg_match('/\$databases\s*\[\s*[\'"]default[\'"]\s*\]\s*\[\s*[\'"]default[\'"]\s*\]\s*=\s*(?:array\s*\(|\[)(.*?)(?:\);|\];)/s', $src, $m)) {
                $src = $m[1];
            }
            $out = ['name' => $arrayKey($src, 'database'), 'user' => $arrayKey($src, 'username'), 'pass' => $arrayKey($src, 'password'),
                'host' => $arrayKey($src, 'host'), 'port' => $arrayKey($src, 'port')];
            break;
        case 'prestashop':
            $src = $read($p . '/app/config/parameters.php');
            if ($src !== '') {
                $out = ['name' => $arrayKey($src, 'database_name'), 'user' => $arrayKey($src, 'database_user'), 'pass' => $arrayKey($src, 'database_password'),
                    'host' => $arrayKey($src, 'database_host'), 'port' => $arrayKey($src, 'database_port')];
            } else {
                $src = $read($p . '/config/settings.inc.php');
                $out = ['name' => $define($src, '_DB_NAME_'), 'user' => $define($src, '_DB_USER_'), 'pass' => $define($src, '_DB_PASSWD_'), 'host' => $define($src, '_DB_SERVER_')];
            }
            break;
        case 'opencart':
            $src = $read($p . '/config.php');
            $out = ['name' => $define($src, 'DB_DATABASE'), 'user' => $define($src, 'DB_USERNAME'), 'pass' => $define($src, 'DB_PASSWORD'),
                'host' => $define($src, 'DB_HOSTNAME'), 'port' => $define($src, 'DB_PORT')];
            break;
        case 'magento':
            $src = $read($p . '/app/etc/env.php');
            $out = ['name' => $arrayKey($src, 'dbname'), 'user' => $arrayKey($src, 'username'), 'pass' => $arrayKey($src, 'password'), 'host' => $arrayKey($src, 'host')];
            break;
        default:
            foreach (['.env', '../.env'] as $f) {
                $env = shield_parse_env($read($p . '/' . $f));
                if (!empty($env['DB_DATABASE']) || !empty($env['DB_NAME'])) {
                    $out = ['name' => $env['DB_DATABASE'] ?? $env['DB_NAME'], 'user' => $env['DB_USERNAME'] ?? $env['DB_USER'] ?? null,
                        'pass' => $env['DB_PASSWORD'] ?? $env['DB_PASS'] ?? null, 'host' => $env['DB_HOST'] ?? null, 'port' => $env['DB_PORT'] ?? null];
                    break;
                }
            }
    }
    if (empty($out['name']) || empty($out['user'])) {
        return [];
    }
    $host = (string)($out['host'] ?: 'localhost');
    $port = (int)($out['port'] ?? 0);
    if (!$port && preg_match('/^(.+):(\d+)$/', $host, $m)) {
        [$host, $port] = [$m[1], (int)$m[2]];
    }
    return ['host' => $host, 'port' => $port ?: 3306, 'user' => (string)$out['user'], 'pass' => (string)($out['pass'] ?? ''), 'name' => (string)$out['name']];
}

function shield_parse_env(string $src): array
{
    $env = [];
    foreach (preg_split('/\R/', $src) as $line) {
        if (preg_match('/^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)$/i', $line, $m)) {
            $v = trim($m[2]);
            if (preg_match('/^"((?:[^"\\\\]|\\\\.)*)"/', $v, $q)) {
                $v = stripcslashes($q[1]);
            } elseif (preg_match("/^'([^']*)'/", $v, $q)) {
                $v = $q[1];
            } else {
                $v = trim((string)preg_replace('/\s+#.*$/', '', $v));
            }
            $env[$m[1]] = $v;
        }
    }
    return $env;
}

/** Laravel and similar serve from public/: the site root to back up is one level up. */
function shield_app_root(string $docroot, string $platform): string
{
    $d = rtrim($docroot, '/');
    if ($platform === 'laravel' && basename($d) === 'public' && is_file(dirname($d) . '/artisan')) {
        return dirname($d);
    }
    return $d;
}

/**
 * Candidate web roots in the hosting account.
 * Uses cPanel's userdata when readable, otherwise scans the home folder two levels deep.
 * Returns [['path', 'domain', 'platform', 'db' => [...]]].
 */
function shield_discover_sites(?string $home = null): array
{
    $home = rtrim(str_replace('\\', '/', $home ?? shield_guess_home()), '/');
    $found = [];

    // cPanel: /var/cpanel/userdata/<user>/<domain> holds "documentroot: /home/user/..."
    $user = basename($home);
    foreach ((array)@glob('/var/cpanel/userdata/' . $user . '/*') as $f) {
        $f = (string)$f;
        if (str_contains(basename($f), '.') && !preg_match('/(_SSL|\.cache|\.json|\.yaml)$/', $f) && is_readable($f)) {
            $src = (string)@file_get_contents($f);
            if (preg_match('/^documentroot:\s*(\S+)/m', $src, $m) && is_dir($m[1])) {
                $found[rtrim($m[1], '/')] = basename($f);
            }
        }
    }

    // Generic scan: folders that look like web roots.
    $skip = ['/mail', '/etc', '/tmp', '/logs', '/ssl', '/.cpanel', '/.trash', '/.cagefs', '/.softaculous', '/perl5', '/.local', '/.cache',
        '/node_modules', '/vendor', '/cgi-bin', '/.well-known', '/wp-content', '/wp-includes', '/wp-admin', '/.git', '/access-logs', '/lscache'];
    $isRoot = static fn(string $d): bool => is_file($d . '/index.php') || is_file($d . '/index.html') || is_file($d . '/wp-config.php') || is_file($d . '/artisan');
    $level1 = array_filter((array)@glob($home . '/*', GLOB_ONLYDIR));
    foreach ($level1 as $d) {
        $d = (string)$d;
        if (in_array(substr($d, strlen($home)), $skip, true)) {
            continue;
        }
        if ($isRoot($d)) {
            $found[$d] ??= str_contains(basename($d), '.') ? basename($d) : '';
        }
        foreach (array_filter((array)@glob($d . '/*', GLOB_ONLYDIR)) as $sub) {
            $sub = (string)$sub;
            $name = basename($sub);
            if (!in_array('/' . $name, $skip, true) && $isRoot($sub) && (str_contains($name, '.') || $name === 'public' || basename($d) === 'public_html')) {
                $found[$sub] ??= str_contains($name, '.') ? $name : '';
            }
        }
    }

    $shieldRoot = rtrim(str_replace('\\', '/', (string)realpath(shield_root())), '/');
    $out = [];
    foreach ($found as $path => $domain) {
        $real = rtrim(str_replace('\\', '/', (string)(realpath($path) ?: $path)), '/');
        if ($real === $shieldRoot) {
            continue;
        }
        $platform = shield_detect_platform($real);
        if ($domain === '' && basename($real) === 'public_html') {
            $domain = shield_guess_main_domain($home);
        }
        $app = shield_app_root($real, $platform);
        if (isset($out[$app]) && ($out[$app]['domain'] !== '' || $domain === '')) {
            continue; // same app found through its docroot and its public/ folder
        }
        $out[$app] = [
            'path' => $app,
            'domain' => $domain !== '' ? $domain : ($out[$app]['domain'] ?? ''),
            'platform' => $platform,
            'db' => shield_detect_db($real, $platform),
        ];
    }
    $out = array_values($out);
    usort($out, static fn($a, $b) => strcmp($a['domain'] ?: $a['path'], $b['domain'] ?: $b['path']));
    return $out;
}

function shield_guess_home(): string
{
    $candidates = [getenv('SHIELD_HOME') ?: '', getenv('HOME') ?: '', $_SERVER['HOME'] ?? ''];
    if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
        $candidates[] = (string)(posix_getpwuid(posix_geteuid())['dir'] ?? '');
    }
    if (preg_match('#^(/home\d*/[^/]+)#', str_replace('\\', '/', shield_root()), $m)) {
        $candidates[] = $m[1];
    }
    foreach ($candidates as $c) {
        if ($c !== '' && is_dir($c) && is_readable($c)) {
            return rtrim(str_replace('\\', '/', $c), '/');
        }
    }
    return dirname(shield_root());
}

function shield_guess_main_domain(string $home): string
{
    $user = basename($home);
    $main = @file_get_contents('/var/cpanel/userdata/' . $user . '/main');
    if ($main && preg_match('/^main_domain:\s*(\S+)/m', $main, $m)) {
        return $m[1];
    }
    return '';
}

/** Builds a site entry from a discovery result. */
function shield_site_from_discovery(array $d): array
{
    $domain = (string)$d['domain'];
    $site = array_replace(shield_site_defaults(), [
        'title' => $domain ?: basename((string)$d['path']),
        'url' => $domain !== '' ? 'https://' . $domain : '',
        'hosts' => $domain !== '' ? [$domain, 'www.' . $domain] : [],
        'path' => (string)$d['path'],
        'platform' => (string)$d['platform'],
        'upload_dirs' => shield_platform_upload_dirs((string)$d['platform'], (string)$d['path']),
        'exclude' => shield_platform_excludes((string)$d['platform']),
    ]);
    if (!empty($d['db'])) {
        $site['db'] = array_intersect_key($d['db'], array_flip(['host', 'port', 'user', 'pass']));
        $site['databases'] = [(string)$d['db']['name']];
    }
    return $site;
}

/** A unique, folder-safe key for a new site. */
function shield_site_key(string $title, array $existing): string
{
    $k = strtolower((string)preg_replace('/[^a-z0-9]+/i', '-', preg_replace('/^www\./i', '', $title)));
    $k = trim($k, '-') ?: 'site';
    $k = substr($k, 0, 40);
    $base = $k;
    for ($i = 2; isset($existing[$k]); $i++) {
        $k = $base . '-' . $i;
    }
    return $k;
}

/** PHP 8.1+ command-line binaries on this server (cPanel, SPanel, CloudLinux, Plesk, DirectAdmin paths). */
function shield_php_cli_binaries(): array
{
    $patterns = ['/opt/cpanel/ea-php*/root/usr/bin/php', '/opt/remi/php*/root/usr/bin/php', '/opt/alt/php*/usr/bin/php',
        '/opt/plesk/php/*/bin/php', '/usr/local/php*/bin/php', '/usr/bin/php[0-9]*', '/usr/local/bin/php[0-9]*', '/opt/php*/bin/php',
        '/usr/local/bin/php', '/usr/bin/php'];
    $out = [];
    foreach ($patterns as $pat) {
        foreach ((array)@glob($pat) as $path) {
            $path = (string)$path;
            if (preg_match('/-(cgi|pear|phar|fpm|config|ize)$/', $path) || !@is_file($path)) {
                continue;
            }
            $norm = str_replace(['ea-php', '/opt/plesk/php/'], ['php', '/opt/plesk/php'], $path);
            if (!preg_match('/php-?(\d)\.?(\d)/', $norm, $m)) {
                continue; // unversioned binaries: we cannot tell the version without running them
            }
            $ver = (int)$m[1] * 10 + (int)$m[2];
            if ($ver >= 81) {
                $out[$path] = ['path' => $path, 'version' => $m[1] . '.' . $m[2], 'v' => $ver];
            }
        }
    }
    // Same version as the web first, then the newest.
    $web = PHP_MAJOR_VERSION * 10 + PHP_MINOR_VERSION;
    usort($out, static fn($a, $b) => [(int)($b['v'] === $web), $b['v']] <=> [(int)($a['v'] === $web), $a['v']]);
    return array_values($out);
}
