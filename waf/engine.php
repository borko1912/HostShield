<?php
// HostShield — request inspection.
// Pure functions: no I/O, no superglobals. The firewall feeds them the live request;
// the tests feed them fixtures.

function shield_ip_in_list(string $ip, array $list): bool
{
    $bin = @inet_pton($ip);
    foreach ($list as $entry) {
        $entry = trim((string)(is_array($entry) ? ($entry['ip'] ?? '') : $entry));
        if ($entry === '') {
            continue;
        }
        if (!str_contains($entry, '/')) {
            if ($entry === $ip) {
                return true;
            }
            continue;
        }
        [$net, $bits] = explode('/', $entry, 2);
        $nb = @inet_pton($net);
        if ($bin === false || $nb === false || strlen($bin) !== strlen($nb)) {
            continue;
        }
        $bits = (int)$bits;
        $bytes = intdiv($bits, 8);
        if (strncmp($bin, $nb, $bytes) !== 0) {
            continue;
        }
        $rem = $bits % 8;
        if ($rem === 0 || ((ord($bin[$bytes]) ^ ord($nb[$bytes])) & (0xFF << (8 - $rem)) & 0xFF) === 0) {
            return true;
        }
    }
    return false;
}

function shield_waf_rules(): array
{
    static $rules = null;
    return $rules ??= require __DIR__ . '/rules.php';
}

/** Lowercase, URL-decode (twice, for double encoding), decode HTML entities, drop inline SQL comments. */
function shield_waf_normalize(string $v): string
{
    $n = strtolower($v);
    for ($i = 0; $i < 2 && str_contains($n, '%'); $i++) {
        $n = rawurldecode($n);
    }
    $n = html_entity_decode($n, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return (string)preg_replace('#/\*(?!!).*?\*/#s', ' ', $n);
}

/** Flattens request data into [where => value] pairs (keys are inspected too). */
function shield_waf_collect(mixed $v, string $where, array &$out, int $depth = 0): void
{
    if (count($out) > 800 || $depth > 8) {
        return;
    }
    if (is_array($v)) {
        foreach ($v as $k => $x) {
            $w = $where . ($depth === 0 ? ':' : '.') . $k;
            if (is_string($k)) {
                $out[] = [$w, $k];
            }
            shield_waf_collect($x, $w, $out, $depth + 1);
        }
    } elseif (is_string($v) && $v !== '' && strlen($v) <= 65536) {
        $out[] = [$where, $v];
    }
}

/**
 * Does a site exception cover this rule on this path?
 * Exceptions: [['rule' => 'xss_script' | '*', 'path' => '/wp-admin/post.php' | '']].
 */
function shield_waf_excepted(string $rule, string $path, array $exceptions): bool
{
    foreach ($exceptions as $ex) {
        $r = (string)($ex['rule'] ?? '*');
        $p = strtolower((string)($ex['path'] ?? ''));
        if (($r === '*' || $r === $rule) && ($p === '' || str_starts_with($path, $p))) {
            return true;
        }
    }
    return false;
}

/**
 * Inspects one request.
 *
 * $req:  method, uri, path (decoded, lowercase), ua, referer, get, post, cookie, body (decoded JSON/XML or null),
 *        files ([[name, tmp_path]]), script (path of the executed file relative to the site root, or null)
 * $waf:  global firewall settings
 * $site: matched site settings (platform, upload_dirs, waf_exceptions, waf_skip_paths)
 *
 * Returns ['hits' => [ruleId => where], 'is_login' => bool].
 */
function shield_waf_inspect(array $req, array $waf, array $site): array
{
    $rules = shield_waf_rules();
    $hits = [];
    $add = static function (string $id, string $where) use (&$hits): void {
        $hits[$id] ??= mb_substr($where, 0, 120);
    };
    $path = (string)($req['path'] ?? '/');
    $platform = (string)($site['platform'] ?? '');

    $ua = strtolower((string)($req['ua'] ?? ''));
    foreach ($rules['scanner_ua'] as $b) {
        if (str_contains($ua, $b)) {
            $add('scanner_ua', $b);
            break;
        }
    }

    $probes = $rules['probes'];
    if ($platform !== 'wordpress') {
        $probes = array_merge($probes, $rules['wp_paths']);
    }
    foreach ($probes as $p) {
        if (str_contains($path, $p)) {
            $add('probe', $p);
            break;
        }
    }
    $uri = (string)($req['uri'] ?? '/');
    if (str_contains($uri, "\0") || stripos($uri, '%00') !== false) {
        $add('null_byte', 'uri');
    }

    if ($platform === 'wordpress') {
        if (!empty($waf['wp_block_xmlrpc']) && str_ends_with($path, '/xmlrpc.php')) {
            $add('wp_xmlrpc', $path);
        }
        if (!empty($waf['wp_block_user_enum'])) {
            $author = $req['get']['author'] ?? null;
            $route = strtolower((string)($req['get']['rest_route'] ?? ''));
            if ((is_string($author) && ctype_digit($author) && !str_starts_with($path, '/wp-admin'))
                || str_contains($path, '/wp-json/wp/v2/users') || str_contains($route, '/wp/v2/users')) {
                $add('wp_user_enum', $path);
            }
        }
    }

    // PHP running from an upload folder is almost always a web shell.
    $script = isset($req['script']) ? strtolower(ltrim((string)$req['script'], '/')) : '';
    if ($script !== '' && !empty($waf['block_exec_in_uploads'])) {
        foreach ((array)($site['upload_dirs'] ?? []) as $u) {
            $u = strtolower(trim((string)$u, '/'));
            if ($u !== '' && str_starts_with($script, $u . '/')) {
                $add('exec_in_uploads', $script);
                break;
            }
        }
    }

    $skip = false;
    foreach ((array)($site['waf_skip_paths'] ?? []) as $sp) {
        if ($sp !== '' && str_starts_with($path, strtolower((string)$sp))) {
            $skip = true;
            break;
        }
    }

    if (!$skip) {
        $values = [['uri', rawurldecode($uri)]];
        shield_waf_collect((array)($req['get'] ?? []), 'GET', $values);
        shield_waf_collect((array)($req['post'] ?? []), 'POST', $values);
        shield_waf_collect((array)($req['cookie'] ?? []), 'COOKIE', $values);
        if (isset($req['body'])) {
            shield_waf_collect($req['body'], 'BODY', $values);
        }
        // Headers only for the header-borne attacks.
        $headerRules = ['log4j', 'shellshock', 'sqli_time', 'sqli_union'];
        foreach (['user-agent' => $req['ua'] ?? '', 'referer' => $req['referer'] ?? ''] as $h => $hv) {
            if ((string)$hv !== '') {
                $n = shield_waf_normalize((string)$hv);
                foreach ($headerRules as $id) {
                    if (preg_match($rules['patterns'][$id][0], $n)) {
                        $add($id, 'HEADER:' . $h);
                    }
                }
            }
        }

        foreach ($values as [$where, $v]) {
            $n = shield_waf_normalize($v);
            if (str_contains($n, "\0")) {
                $add('null_byte', $where);
            }
            foreach ($rules['patterns'] as $id => [$re]) {
                if (!isset($hits[$id]) && preg_match($re, $n)) {
                    $add($id, $where);
                }
            }
        }
    }

    foreach ((array)($req['files'] ?? []) as [$name, $tmp]) {
        $ln = strtolower((string)$name);
        if (preg_match($rules['upload_ext'], $ln)) {
            $add('upload_script', (string)$name);
        } elseif ($tmp !== '' && is_file((string)$tmp) && filesize((string)$tmp) <= 20 * 1048576) {
            $h = @fopen((string)$tmp, 'rb');
            $prev = '';
            while ($h && !feof($h)) {
                $chunk = $prev . fread($h, 1048576);
                if (stripos($chunk, '<?php') !== false) {
                    $add('upload_php_code', (string)$name);
                    break;
                }
                $prev = substr($chunk, -8);
            }
            $h && fclose($h);
        }
    }

    $isLogin = false;
    if (strtoupper((string)($req['method'] ?? 'GET')) === 'POST') {
        foreach (array_keys((array)($req['post'] ?? [])) as $k) {
            if (is_string($k) && preg_match($rules['login_fields'], $k)) {
                $isLogin = true;
                break;
            }
        }
    }

    $exceptions = (array)($site['waf_exceptions'] ?? []);
    $disabled = array_flip((array)($site['waf_disabled_rules'] ?? []));
    foreach (array_keys($hits) as $id) {
        if (isset($disabled[$id]) || ($exceptions && shield_waf_excepted($id, $path, $exceptions))) {
            unset($hits[$id]);
        }
    }
    return ['hits' => $hits, 'is_login' => $isLogin];
}

/** Rule id => [category, description] for every rule the firewall can raise. */
function shield_waf_rule_catalog(): array
{
    $r = shield_waf_rules();
    $out = [];
    foreach ($r['patterns'] as $id => [, $cat, $desc]) {
        $out[$id] = [$cat, $desc];
    }
    return $out + $r['other'];
}
