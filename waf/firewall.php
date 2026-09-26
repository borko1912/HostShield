<?php
// HostShield — Web Application Firewall.
// Runs before every PHP request of a protected site (auto_prepend_file).
// Fail-open: on any internal error the site keeps working normally.

(static function (): void {
    if (PHP_SAPI === 'cli' || defined('SHIELD_WAF_LOADED')) {
        return;
    }
    define('SHIELD_WAF_LOADED', true);

    try {
        $configFile = (string)(getenv('SHIELD_CONFIG') ?: dirname(__DIR__) . '/config.php');
        if (!is_file($configFile)) {
            return;
        }
        $boot = (array)(require $configFile);
        $data = rtrim((string)($boot['data_dir'] ?? ''), '/\\');
        if ($data === '') {
            return;
        }
        $cfg = is_file($data . '/settings.php') ? (array)(include $data . '/settings.php') : $boot;
        require_once __DIR__ . '/engine.php';

        $waf = (array)($cfg['waf'] ?? []);
        $dir = $data . '/waf';
        $now = time();

        // --- which site ---
        $host = strtolower((string)preg_replace('/:\d+$/', '', (string)($_SERVER['HTTP_HOST'] ?? '')));
        $scriptFile = str_replace('\\', '/', (string)($_SERVER['SCRIPT_FILENAME'] ?? ''));
        $siteKey = '_other';
        $site = [];
        foreach ((array)($cfg['sites'] ?? []) as $k => $s) {
            if (in_array($host, array_map('strtolower', (array)($s['hosts'] ?? [])), true)) {
                $siteKey = (string)$k;
                $site = (array)$s;
                break;
            }
        }
        if ($siteKey === '_other' && $scriptFile !== '') {
            foreach ((array)($cfg['sites'] ?? []) as $k => $s) {
                $p = rtrim(str_replace('\\', '/', (string)($s['path'] ?? '')), '/');
                if ($p !== '' && str_starts_with($scriptFile, $p . '/')) {
                    $siteKey = (string)$k;
                    $site = (array)$s;
                    break;
                }
            }
        }
        $sitePath = rtrim(str_replace('\\', '/', (string)($site['path'] ?? '')), '/');
        $scriptRel = $sitePath !== '' && str_starts_with($scriptFile, $sitePath . '/') ? substr($scriptFile, strlen($sitePath) + 1) : null;
        $mode = (string)(($site['waf_mode'] ?? null) ?: ($waf['mode'] ?? 'log'));

        // --- heartbeat: lets the dashboard see the firewall is active ---
        $hb = $dir . '/heartbeat/' . $siteKey;
        if (!is_file($hb) || $now - (int)@filemtime($hb) > 60) {
            @is_dir(dirname($hb)) || @mkdir(dirname($hb), 0700, true);
            @touch($hb);
        }

        // --- maintenance while a restore runs ---
        if ($siteKey !== '_other' && is_file($dir . '/maintenance/' . $siteKey)) {
            http_response_code(503);
            header('Retry-After: 120');
            header('Content-Type: text/html; charset=utf-8');
            echo '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Maintenance</title>'
                . '<div style="font:16px system-ui;padding:60px 20px;text-align:center"><h1>Down for maintenance</h1>'
                . '<p>The site is being restored. Please try again in a few minutes.</p></div>';
            exit;
        }
        if ($mode === 'off') {
            return;
        }

        // --- IP (behind a trusted proxy use the forwarded address) ---
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        $proxies = (array)($waf['trusted_proxies'] ?? []);
        if ($proxies && shield_ip_in_list($ip, $proxies)) {
            $fwd = (string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
            $fwd = trim(explode(',', $fwd)[0]);
            if (filter_var($fwd, FILTER_VALIDATE_IP)) {
                $ip = $fwd;
            }
        }
        $ipKey = preg_replace('/[^0-9a-f]/i', '_', $ip);
        $method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $uri = (string)($_SERVER['REQUEST_URI'] ?? '/');
        $path = strtolower(rawurldecode((string)parse_url($uri, PHP_URL_PATH)));
        $ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');

        // --- HostShield's own requests (uptime monitor, security audit) ---
        // Rules still apply, but no strikes, bans, rate limits or attack log:
        // the audit probes /.env, /.git … on purpose. See shield_internal_key().
        $internal = false;
        $ik = (string)($_SERVER['HTTP_X_HOSTSHIELD_INTERNAL'] ?? '');
        if ($ik !== '' && is_file($dir . '/internal.key')) {
            $internal = hash_equals(trim((string)@file_get_contents($dir . '/internal.key')), $ik);
        }

        // --- optional "Protected by" badge ---
        $banner = (array)($cfg['banner'] ?? []);
        $bShow = (string)($banner['show'] ?? 'session');
        if (!empty($banner['enabled']) && ($site['banner'] ?? true) && $siteKey !== '_other'
            && $method === 'GET' && ($bShow === 'always' || empty($_COOKIE['hostshield_seen']))
            && empty($_SERVER['HTTP_X_REQUESTED_WITH'])
            && str_contains((string)($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html')
            && in_array((string)($_SERVER['HTTP_SEC_FETCH_DEST'] ?? 'document'), ['document', ''], true)) {
            $text = htmlspecialchars((string)($banner['text'] ?? 'Protected by HostShield'), ENT_QUOTES, 'UTF-8');
            $cookie = $bShow === 'always' ? '' : 'hostshield_seen=1; path=/; SameSite=Lax' . ($bShow === 'once' ? '; max-age=31536000' : '');
            $ms = max(1000, (int)round(1000 * (float)($banner['seconds'] ?? 4)));
            ob_start(static function (string $out) use ($text, $cookie, $ms): string {
                foreach (headers_list() as $h) {
                    $hl = strtolower($h);
                    if ((str_starts_with($hl, 'content-type:') && !str_contains($hl, 'text/html'))
                        || str_starts_with($hl, 'content-length:') || str_starts_with($hl, 'content-disposition:')) {
                        return $out;
                    }
                }
                $code = http_response_code();
                $pos = strripos($out, '</body>');
                if ($pos === false || ($code !== false && $code !== 200)) {
                    return $out;
                }
                $html = '<div id="hostshield-badge" role="status" style="position:fixed;right:16px;bottom:16px;z-index:2147483647;display:flex;align-items:center;gap:8px;'
                    . 'padding:8px 10px 8px 14px;border-radius:999px;background:rgba(17,20,24,.92);color:#fff;font:600 13px/1.2 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;'
                    . 'box-shadow:0 6px 24px rgba(0,0,0,.25);opacity:0;transform:translateY(8px);transition:opacity .4s,transform .4s;max-width:calc(100vw - 32px)">'
                    . '<span aria-hidden="true" style="font-size:15px">🛡</span><span>' . $text . '</span>'
                    . '<button type="button" aria-label="Close" style="all:unset;cursor:pointer;padding:0 6px;font-size:16px;opacity:.7">&times;</button></div>'
                    . '<script>(function(){' . ($cookie !== '' ? 'try{document.cookie="' . $cookie . '"}catch(e){}' : '')
                    . 'var b=document.getElementById("hostshield-badge");if(!b)return;var h=function(){b.style.opacity="0";b.style.transform="translateY(8px)";setTimeout(function(){b.remove()},450)};'
                    . 'b.querySelector("button").onclick=h;requestAnimationFrame(function(){b.style.opacity="1";b.style.transform="none"});setTimeout(h,' . $ms . ')})();</script>';
                return substr($out, 0, $pos) . $html . substr($out, $pos);
            });
        }

        // --- allow list ---
        if (shield_ip_in_list($ip, array_merge((array)($waf['allow_ips'] ?? []), (array)($waf['allow'] ?? [])))) {
            return;
        }

        $log = static function (string $action, array $hits) use ($data, $now, $siteKey, $ip, $method, $uri, $ua, $mode): string {
            $id = strtoupper(bin2hex(random_bytes(4)));
            $line = json_encode([
                't' => $now, 'id' => $id, 'site' => $siteKey, 'ip' => $ip, 'm' => $method,
                'uri' => mb_substr($uri, 0, 400), 'ua' => mb_substr($ua, 0, 200),
                'rules' => array_keys($hits), 'where' => $hits, 'action' => $action, 'mode' => $mode,
            ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            @is_dir($data . '/logs') || @mkdir($data . '/logs', 0700, true);
            @file_put_contents($data . '/logs/waf-' . date('Y-m-d', $now) . '.jsonl', $line . "\n", FILE_APPEND | LOCK_EX);
            return $id;
        };

        $deny = static function (string $id, int $code = 403) use ($uri): never {
            http_response_code($code);
            header('Cache-Control: no-store');
            $accept = (string)($_SERVER['HTTP_ACCEPT'] ?? '');
            if (str_contains($accept, 'json') || str_contains($uri, '/api') || str_contains($uri, 'wp-json')) {
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['ok' => false, 'error' => 'blocked_by_firewall', 'id' => $id]);
            } else {
                $bg = str_starts_with(strtolower((string)($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')), 'bg');
                $title = $code === 429 ? ($bg ? 'Твърде много заявки' : 'Too many requests') : ($bg ? 'Достъпът е блокиран' : 'Access denied');
                $msg = $bg ? 'Ако смятате, че това е грешка, изпратете на администратора този код:' : 'If you think this is a mistake, send this code to the site administrator:';
                header('Content-Type: text/html; charset=utf-8');
                echo '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . $title . '</title>'
                    . '<div style="font:16px system-ui;padding:60px 20px;text-align:center;color:#1b1f24"><div style="font-size:42px">🛡</div><h1>' . $title . '</h1>'
                    . '<p>' . $msg . ' <b style="font-family:ui-monospace,monospace">' . htmlspecialchars($id) . '</b></p></div>';
            }
            exit;
        };

        // --- active ban / block list ---
        $banFile = $dir . '/bans/' . $ipKey . '.json';
        if (!$internal && is_file($banFile)) {
            $ban = (array)json_decode((string)@file_get_contents($banFile), true);
            if ((int)($ban['until'] ?? 0) > $now) {
                $deny('BAN', 403);
            }
            @unlink($banFile);
        }
        if (!$internal && shield_ip_in_list($ip, array_merge((array)($waf['block_ips'] ?? []), (array)($waf['block'] ?? [])))) {
            $deny($log('blocked', ['blocklist' => $ip]));
        }

        // --- counters (APCu when available, files otherwise) ---
        $bump = static function (string $name, int $window) use ($dir, $now): int {
            if (function_exists('apcu_inc') && ini_get('apc.enabled')) {
                $n = apcu_inc('shield:' . $name . ':' . intdiv($now, $window), 1, $ok, $window + 5);
                if ($n !== false) {
                    return (int)$n;
                }
            }
            $f = $dir . '/rate/' . $name . '-' . intdiv($now, $window);
            @is_dir(dirname($f)) || @mkdir(dirname($f), 0700, true);
            $h = @fopen($f, 'c+');
            if (!$h) {
                return 0;
            }
            flock($h, LOCK_EX);
            $n = (int)stream_get_contents($h) + 1;
            ftruncate($h, 0);
            rewind($h);
            fwrite($h, (string)$n);
            flock($h, LOCK_UN);
            fclose($h);
            return $n;
        };

        // --- inspection ---
        $body = null;
        $ct = strtolower((string)($_SERVER['CONTENT_TYPE'] ?? ''));
        if ($method !== 'GET' && (str_contains($ct, 'json') || str_contains($ct, 'xml'))) {
            $raw = (string)@file_get_contents('php://input', false, null, 0, 262144);
            $j = str_contains($ct, 'json') ? json_decode($raw, true) : null;
            $body = is_array($j) ? $j : $raw;
        }
        $files = [];
        $walk = static function ($names, $tmps) use (&$walk, &$files): void {
            if (is_array($names)) {
                foreach ($names as $k => $n) {
                    $walk($n, $tmps[$k] ?? null);
                }
            } elseif (is_string($names) && $names !== '') {
                $files[] = [$names, is_string($tmps) ? $tmps : ''];
            }
        };
        foreach ($_FILES as $f) {
            $walk($f['name'] ?? null, $f['tmp_name'] ?? null);
        }

        $res = shield_waf_inspect([
            'method' => $method, 'uri' => $uri, 'path' => $path, 'ua' => $ua,
            'referer' => (string)($_SERVER['HTTP_REFERER'] ?? ''),
            'get' => $_GET, 'post' => $_POST, 'cookie' => $_COOKIE, 'body' => $body,
            'files' => $files, 'script' => $scriptRel,
        ], $waf, $site);
        $hits = $res['hits'];
        $disabled = array_flip((array)($site['waf_disabled_rules'] ?? []));

        // Lockdown: only scripts from the approved list may run.
        if (!empty($site['lockdown']) && $scriptRel !== null && !isset($disabled['exec_not_allowed'])) {
            $allowFile = $dir . '/exec-' . $siteKey . '.php';
            if (is_file($allowFile)) {
                $allowed = (array)(include $allowFile);
                if (!isset($allowed[$scriptRel]) && !shield_waf_excepted('exec_not_allowed', $path, (array)($site['waf_exceptions'] ?? []))) {
                    $hits['exec_not_allowed'] = $scriptRel;
                }
            }
        }

        $limit = (int)($waf['rate_limit_per_min'] ?? 600);
        if (!$internal && $limit > 0 && !isset($disabled['rate_limit']) && $bump('r' . $ipKey, 60) > $limit) {
            $hits['rate_limit'] = $limit . '/min';
        }
        if (!$internal && $res['is_login'] && !isset($disabled['login_bruteforce'])) {
            $lw = (int)($waf['login_window'] ?? 600);
            $ll = (int)($waf['login_limit'] ?? 10);
            if ($bump('l' . $ipKey, $lw) > $ll) {
                $hits['login_bruteforce'] = $ll . '/' . $lw . 's';
            }
        }

        if (!$hits) {
            return;
        }
        if ($internal) {
            // The audit needs the real answer (403 = file protected), nothing else.
            if ($mode === 'block') {
                $deny('INTERNAL', 403);
            }
            return;
        }
        if ($mode !== 'block') {
            $log('logged', $hits);
            return;
        }

        // --- strike, then ban on repeat offenders (1h, 2h, 4h ... up to 7 days) ---
        $sf = $dir . '/strikes/' . $ipKey . '.json';
        @is_dir(dirname($sf)) || @mkdir(dirname($sf), 0700, true);
        $s = is_file($sf) ? (array)json_decode((string)@file_get_contents($sf), true) : [];
        if ($now - (int)($s['first'] ?? 0) > (int)($waf['strike_window'] ?? 600)) {
            $s['first'] = $now;
            $s['count'] = 0;
        }
        $s['count'] = (int)($s['count'] ?? 0) + 1;
        $action = 'blocked';
        if ($s['count'] >= (int)($waf['strikes_to_ban'] ?? 3)) {
            $s['bans'] = (int)($s['bans'] ?? 0) + 1;
            $minutes = min(10080, (int)($waf['ban_minutes'] ?? 60) * (2 ** ($s['bans'] - 1)));
            @is_dir(dirname($banFile)) || @mkdir(dirname($banFile), 0700, true);
            @file_put_contents($banFile, json_encode(['ip' => $ip, 'since' => $now, 'until' => $now + $minutes * 60,
                'site' => $siteKey, 'rules' => array_keys($hits), 'uri' => mb_substr($uri, 0, 200)]), LOCK_EX);
            $s['count'] = 0;
            $action = 'banned';
            @file_put_contents($dir . '/alerts.jsonl', json_encode(['t' => $now, 'ip' => $ip, 'site' => $siteKey,
                'minutes' => $minutes, 'rules' => array_keys($hits)]) . "\n", FILE_APPEND | LOCK_EX);
        }
        @file_put_contents($sf, json_encode($s), LOCK_EX);

        $throttleOnly = !array_diff(array_keys($hits), ['login_bruteforce', 'rate_limit']);
        $deny($log($action, $hits), $throttleOnly ? 429 : 403);
    } catch (Throwable $e) {
        error_log('[hostshield] ' . $e->getMessage() . ' @' . basename($e->getFile()) . ':' . $e->getLine());
    }
})();
