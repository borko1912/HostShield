<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

// Malware scanner and quarantine.

/** Extensions we watch for changes (executable code and server configuration). */
const SHIELD_WATCH_EXT = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'inc', 'htaccess', 'ini', 'js', 'sh', 'pl', 'py', 'cgi'];
const SHIELD_CODE_EXT = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'inc'];

/**
 * Signatures of web shells and injected code: id => [regex, confidence, applies to].
 * confidence: high = almost never legitimate (eligible for auto-quarantine), medium = review.
 * applies to: code | config | js
 */
function shield_malware_signatures(): array
{
    return [
        'eval_obfuscated'  => ['/\b(eval|assert)\s*\(\s*(@?\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode|convert_uudecode)\s*\()/i', 'high', 'code'],
        'request_exec'     => ['/\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*@?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/i', 'high', 'code'],
        'request_func'     => ['/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/i', 'high', 'code'],
        'request_write'    => ['/file_put_contents\s*\([^;]{0,200}\$_(POST|GET|REQUEST|COOKIE)\b/i', 'medium', 'code'],
        'preg_e'           => ['/preg_replace\s*\(\s*[\'"](.).*\1[imsx]*e[imsx]*[\'"]\s*,/i', 'high', 'code'],
        'create_function'  => ['/\bcreate_function\s*\(/i', 'medium', 'code'],
        'shell_names'      => ['/\b(FilesMan|WSOsetcookie|c99shell|r57shell|b374k|IndoXploit|AnonymousFox|Alfa\s*Shell|ALFA_DATA|wso\s*shell|Mini\s*Shell|Priv8|Gecko\s*Shell|Sh3ll|0x5a455553)\b/i', 'high', 'code'],
        'shell_recon'      => ['/\b(php_uname|posix_getpwuid)\s*\(.{0,400}\b(shell_exec|passthru|system|proc_open)\s*\(/is', 'medium', 'code'],
        'long_base64'      => ['/[\'"][A-Za-z0-9+\/]{3000,}={0,2}[\'"]/', 'medium', 'code'],
        'hex_obfuscation'  => ['/(\\\\x[0-9a-f]{2}){40,}/i', 'medium', 'code'],
        'chr_obfuscation'  => ['/(chr\s*\(\s*\d+\s*\)\s*\.\s*){15,}/i', 'medium', 'code'],
        'goto_obfuscation' => ['/(goto\s+[a-z0-9_]+;\s*){20,}/i', 'medium', 'code'],
        'var_func_global'  => ['/\$\{\s*["\']\\\\x[0-9a-f]{2}/i', 'high', 'code'],
        'fake_image_php'   => ['/^\s*GIF8[79]a.{0,200}<\?php/is', 'high', 'code'],
        'remote_include'   => ['/\b(include|require)(_once)?\s*\(?\s*[\'"]https?:\/\//i', 'high', 'code'],
        'ini_hijack'       => ['/^\s*(php_value\s+)?(auto_prepend_file|auto_append_file)\s*=?\s*(?!.*\/waf\/firewall\.php)\S/im', 'high', 'config'],
        'seo_redirect'     => ['/RewriteCond\s+%\{HTTP_(REFERER|USER_AGENT)\}[^\n]*(google|bing|yahoo|yandex|facebook)[^\n]*\n(\s*RewriteCond[^\n]*\n)*\s*RewriteRule[^\n]*https?:\/\//i', 'high', 'config'],
        'js_injection'     => ['/eval\s*\(\s*String\.fromCharCode\s*\(|document\.write\s*\(\s*unescape\s*\(|\bvar\s+_0x[a-f0-9]{4,}\s*=\s*\[.{0,200}\\\\x68\\\\x74\\\\x74\\\\x70/is', 'medium', 'js'],
    ];
}

/** Scans one file. Returns ['rules' => [...], 'level' => 'high'|'medium'] or [] when clean. */
function shield_scan_file(string $file, bool $inUploads): array
{
    $hits = [];
    $level = 'medium';
    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
    $base = strtolower(basename($file));
    $isCode = in_array($ext, SHIELD_CODE_EXT, true);
    $isConfig = in_array($base, ['.htaccess', '.user.ini', 'php.ini'], true);
    if ($inUploads && ($isCode || $base === '.htaccess' || $base === '.user.ini')) {
        $hits[] = 'code_in_uploads';
        $level = 'high';
    }
    if (@filesize($file) > 5 * 1048576) {
        return $hits ? ['rules' => $hits, 'level' => $level] : [];
    }
    $c = (string)@file_get_contents($file);
    if ($c !== '') {
        $kind = $isConfig ? 'config' : ($ext === 'js' ? 'js' : 'code');
        foreach (shield_malware_signatures() as $name => [$re, $conf, $applies]) {
            if ($applies === $kind && preg_match($re, $c)) {
                $hits[] = $name;
                if ($conf === 'high') {
                    $level = 'high';
                }
            }
        }
        if (!$isCode && !$isConfig && stripos($c, '<?php') !== false
            && !in_array($ext, ['md', 'txt', 'json', 'html', 'htm', 'tpl', 'twig', 'xml', 'yml', 'yaml', 'dist', 'stub', 'sample', 'example', 'lock', 'po', 'pot', 'rst', 'js', 'css', 'svg', 'neon', 'latte', 'phpt'], true)) {
            $hits[] = 'php_in_non_php';
            if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp', 'pdf', 'zip'], true)) {
                $level = 'high';
            }
        }
    }
    return $hits ? ['rules' => array_values(array_unique($hits)), 'level' => $level] : [];
}

function shield_in_uploads(string $rel, array $site): bool
{
    foreach ((array)($site['upload_dirs'] ?? []) as $u) {
        $u = trim((string)$u, '/');
        if ($u !== '' && str_starts_with($rel, $u . '/')) {
            return true;
        }
    }
    return false;
}

// ------------------------------------------------------------------ quarantine

/** Moves a file out of the site into the quarantine. Returns the quarantine id. */
function shield_quarantine_file(string $siteKey, string $rel, array $rules = []): string
{
    $site = shield_site($siteKey);
    $rel = ltrim(str_replace('\\', '/', $rel), '/');
    if ($rel === '' || str_contains('/' . $rel . '/', '/../')) {
        throw new RuntimeException('Invalid path');
    }
    $src = $site['path'] . '/' . $rel;
    if (!is_file($src) || is_link($src)) {
        throw new RuntimeException(__('File not found: %s', $rel));
    }
    $id = date('YmdHis') . '-' . bin2hex(random_bytes(3));
    $dir = shield_dir('quarantine/' . $siteKey . '/' . $id);
    $meta = ['id' => $id, 'rel' => $rel, 'sha1' => (string)sha1_file($src), 'size' => (int)filesize($src),
        'perms' => substr(sprintf('%o', fileperms($src)), -4), 't' => time(), 'rules' => array_values($rules)];
    if (!@rename($src, $dir . '/file.bin')) {
        if (!@copy($src, $dir . '/file.bin') || !@unlink($src)) {
            @unlink($dir . '/file.bin');
            @rmdir($dir);
            throw new RuntimeException(__('Cannot move %s (permissions?)', $rel));
        }
    }
    @chmod($dir . '/file.bin', 0600);
    shield_json_write($dir . '/meta.json', $meta);

    // Forget the file in the integrity report and baseline so it does not come back as "removed".
    $rf = shield_path('integrity/' . $siteKey . '.report.json');
    $rep = shield_json_read($rf);
    unset($rep['malware'][$rel], $rep['added'][$rel], $rep['modified'][$rel]);
    $rep && shield_json_write($rf, $rep);
    $bf = shield_path('integrity/' . $siteKey . '.baseline.json');
    $base = shield_json_read($bf);
    if (isset($base['files'][$rel])) {
        unset($base['files'][$rel]);
        shield_json_write($bf, $base);
    }
    shield_log('quarantine', "{$siteKey}/{$rel} → {$id} [" . implode(',', $rules) . ']');
    return $id;
}

function shield_quarantine_list(string $siteKey): array
{
    $out = [];
    foreach ((array)glob(shield_path('quarantine/' . $siteKey) . '/*/meta.json') as $f) {
        $m = shield_json_read((string)$f);
        if ($m) {
            $out[] = $m;
        }
    }
    usort($out, static fn($a, $b) => $b['t'] <=> $a['t']);
    return $out;
}

function shield_quarantine_restore(string $siteKey, string $id): string
{
    if (!preg_match('/^\d{14}-[0-9a-f]{6}$/', $id)) {
        throw new RuntimeException('Invalid id');
    }
    $site = shield_site($siteKey);
    $dir = shield_path('quarantine/' . $siteKey . '/' . $id);
    $m = shield_json_read($dir . '/meta.json');
    if (!$m || !is_file($dir . '/file.bin')) {
        throw new RuntimeException(__('Not found in quarantine'));
    }
    $target = $site['path'] . '/' . $m['rel'];
    if (file_exists($target)) {
        throw new RuntimeException(__('A file already exists at %s', $m['rel']));
    }
    is_dir(dirname($target)) || mkdir(dirname($target), 0755, true);
    if (!@rename($dir . '/file.bin', $target) && !@copy($dir . '/file.bin', $target)) {
        throw new RuntimeException(__('Cannot write %s', $m['rel']));
    }
    @chmod($target, octdec((string)($m['perms'] ?? '0644')) ?: 0644);
    shield_rrmdir($dir);
    shield_log('quarantine', "Restored {$siteKey}/{$m['rel']}");
    return (string)$m['rel'];
}

function shield_quarantine_delete(string $siteKey, string $id): void
{
    if (!preg_match('/^\d{14}-[0-9a-f]{6}$/', $id)) {
        throw new RuntimeException('Invalid id');
    }
    shield_rrmdir(shield_path('quarantine/' . $siteKey . '/' . $id));
    shield_log('quarantine', "Deleted {$siteKey}/{$id}");
}
