<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

// WordPress integrity: compares core and plugin files with the official checksums
// published by wordpress.org. A modified core file or an unknown PHP file inside
// wp-admin/ or wp-includes/ is a strong sign of a compromise.

function shield_wp_root(array $site): string
{
    return rtrim((string)$site['path'], '/');
}

function shield_wp_version(string $root): array
{
    $src = (string)@file_get_contents($root . '/wp-includes/version.php');
    $ver = preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $src, $m) ? $m[1] : '';
    $locale = preg_match('/\$wp_local_package\s*=\s*[\'"]([^\'"]+)[\'"]/', $src, $m) ? $m[1] : 'en_US';
    return ['version' => $ver, 'locale' => $locale];
}

/** Cached JSON from wordpress.org (checksums never change for a given version). */
function shield_wp_api(string $url, string $cacheName, int $ttl = 0): ?array
{
    $cache = shield_path('cache/' . $cacheName . '.json');
    if (is_file($cache) && ($ttl === 0 || time() - filemtime($cache) < $ttl)) {
        return shield_json_read($cache) ?: null;
    }
    $r = shield_http($url, ['timeout' => 30]);
    if ($r['code'] !== 200) {
        return null;
    }
    $d = json_decode($r['body'], true);
    if (!is_array($d)) {
        return null;
    }
    shield_json_write($cache, $d);
    return $d;
}

function shield_wp_core_checksums(string $version, string $locale): ?array
{
    $safe = preg_replace('/[^A-Za-z0-9_.-]/', '', $version . '-' . $locale);
    $d = shield_wp_api('https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($version) . '&locale=' . rawurlencode($locale), 'wp-core-' . $safe);
    if ((!$d || empty($d['checksums'])) && $locale !== 'en_US') {
        return shield_wp_core_checksums($version, 'en_US');
    }
    $sums = $d['checksums'] ?? null;
    if (is_array($sums) && isset($sums[$version]) && is_array($sums[$version])) {
        $sums = $sums[$version];
    }
    return is_array($sums) && $sums ? $sums : null;
}

/** Latest WordPress release (cached 12 h). */
function shield_wp_latest(): string
{
    $d = shield_wp_api('https://api.wordpress.org/core/version-check/1.7/', 'wp-latest', 43200);
    return (string)($d['offers'][0]['current'] ?? '');
}

/** Plugins: slug => ['version', 'name', 'file']. */
function shield_wp_plugins(string $root): array
{
    $out = [];
    foreach ((array)glob($root . '/wp-content/plugins/*', GLOB_ONLYDIR) as $dir) {
        $slug = basename((string)$dir);
        foreach ((array)glob($dir . '/*.php') as $f) {
            $head = (string)@file_get_contents((string)$f, false, null, 0, 8192);
            if (preg_match('/^[ \t\/*#@]*Plugin Name:\s*(.+)$/mi', $head, $n)) {
                $ver = preg_match('/^[ \t\/*#@]*Version:\s*([^\s*]+)/mi', $head, $v) ? $v[1] : '';
                $out[$slug] = ['version' => $ver, 'name' => trim($n[1]), 'file' => basename((string)$f)];
                break;
            }
        }
    }
    return $out;
}

/**
 * Full verification.
 * Returns ['checked', 'version', 'latest', 'modified' => [], 'unknown' => [], 'missing' => [], 'plugins' => [slug => [...]], 'error']
 */
function shield_wp_verify(array $site): array
{
    $root = shield_wp_root($site);
    $v = shield_wp_version($root);
    $res = ['checked' => time(), 'version' => $v['version'], 'latest' => '', 'modified' => [], 'unknown' => [], 'missing' => [], 'plugins' => []];
    if ($v['version'] === '') {
        $res['error'] = __('WordPress version not found');
        return $res;
    }
    $res['latest'] = shield_wp_latest();
    $sums = shield_wp_core_checksums($v['version'], $v['locale']);
    if (!$sums) {
        $res['error'] = __('Could not get checksums from wordpress.org');
    } else {
        foreach ($sums as $rel => $md5) {
            if (str_starts_with($rel, 'wp-content/')) {
                continue; // themes/plugins shipped with core are updated separately
            }
            $f = $root . '/' . $rel;
            if (!is_file($f)) {
                $res['missing'][] = $rel;
            } elseif (!hash_equals((string)$md5, (string)md5_file($f))) {
                $res['modified'][] = $rel;
            }
        }
        // PHP files that core does not ship, inside core folders.
        foreach (['wp-admin', 'wp-includes'] as $d) {
            if (!is_dir($root . '/' . $d)) {
                continue;
            }
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/' . $d, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS));
            foreach ($it as $f) {
                $rel = substr(str_replace('\\', '/', $f->getPathname()), strlen($root) + 1);
                if (in_array(strtolower($f->getExtension()), ['php', 'phtml', 'phar', 'inc'], true) && !isset($sums[$rel])) {
                    $res['unknown'][] = $rel;
                }
            }
        }
        foreach ((array)glob($root . '/*.php') as $f) {
            $rel = basename((string)$f);
            if (!isset($sums[$rel]) && $rel !== 'wp-config.php') {
                $res['unknown'][] = $rel;
            }
        }
    }

    foreach (shield_wp_plugins($root) as $slug => $p) {
        $entry = ['name' => $p['name'], 'version' => $p['version'], 'status' => 'unverified', 'modified' => [], 'unknown' => []];
        if ($p['version'] !== '' && preg_match('/^[a-z0-9_-]+$/i', $slug) && preg_match('/^[A-Za-z0-9_.-]+$/', $p['version'])) {
            $d = shield_wp_api('https://downloads.wordpress.org/plugin-checksums/' . $slug . '/' . $p['version'] . '.json', 'wp-plugin-' . $slug . '-' . $p['version']);
            if ($d && !empty($d['files'])) {
                $entry['status'] = 'ok';
                $dir = $root . '/wp-content/plugins/' . $slug;
                foreach ((array)$d['files'] as $rel => $h) {
                    $f = $dir . '/' . $rel;
                    if (!is_file($f)) {
                        continue;
                    }
                    $expected = (array)($h['md5'] ?? []);
                    if (!in_array(md5_file($f), $expected, true)) {
                        $entry['modified'][] = $rel;
                    }
                }
                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS));
                foreach ($it as $f) {
                    $rel = substr(str_replace('\\', '/', $f->getPathname()), strlen($dir) + 1);
                    if (in_array(strtolower($f->getExtension()), ['php', 'phtml', 'phar'], true) && !isset($d['files'][$rel])) {
                        $entry['unknown'][] = $rel;
                    }
                }
                if ($entry['modified'] || $entry['unknown']) {
                    $entry['status'] = 'changed';
                }
            }
        }
        $res['plugins'][$slug] = $entry;
    }
    return $res;
}

/** WordPress settings worth checking in the audit. */
function shield_wp_config_flags(string $root): array
{
    $f = is_file($root . '/wp-config.php') ? $root . '/wp-config.php' : dirname($root) . '/wp-config.php';
    $src = (string)@file_get_contents($f);
    $flag = static fn(string $name): ?bool => preg_match('/define\s*\(\s*[\'"]' . $name . '[\'"]\s*,\s*(true|false|1|0)\s*\)/i', $src, $m)
        ? in_array(strtolower($m[1]), ['true', '1'], true) : null;
    return [
        'file' => $f,
        'debug' => (bool)$flag('WP_DEBUG'),
        'debug_display' => $flag('WP_DEBUG_DISPLAY'),
        'file_edit_disabled' => (bool)$flag('DISALLOW_FILE_EDIT') || (bool)$flag('DISALLOW_FILE_MODS'),
        'default_prefix' => (bool)preg_match('/\$table_prefix\s*=\s*[\'"]wp_[\'"]/', $src),
        'salts_default' => str_contains($src, 'put your unique phrase here'),
    ];
}
