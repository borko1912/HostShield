<?php
// Pure helpers: TOTP, SigV4, retention, IP lists, config parsing, settings migration.

test('totp: RFC 6238 SHA-1 vectors (last 6 digits)', function (): void {
    $secret = shield_base32_encode('12345678901234567890');
    eq('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', $secret, 'base32');
    eq('12345678901234567890', shield_base32_decode($secret), 'base32 roundtrip');
    foreach ([59 => '287082', 1111111109 => '081804', 1234567890 => '005924', 2000000000 => '279037'] as $t => $code) {
        eq($code, shield_totp($secret, intdiv($t, 30)), "T={$t}");
    }
});

test('sigv4: AWS documentation examples', function (): void {
    $key = 'AKIAIOSFODNN7EXAMPLE';
    $secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    $empty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    $auth = shield_sigv4('GET', '/test.txt', [], [
        'host' => 'examplebucket.s3.amazonaws.com', 'range' => 'bytes=0-9',
        'x-amz-content-sha256' => $empty, 'x-amz-date' => '20130524T000000Z',
    ], $empty, $key, $secret, 'us-east-1', '20130524T000000Z');
    ok(str_ends_with($auth, 'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'), 'GET object: ' . $auth);
    $auth = shield_sigv4('GET', '/', ['max-keys' => '2', 'prefix' => 'J'], [
        'host' => 'examplebucket.s3.amazonaws.com', 'x-amz-content-sha256' => $empty, 'x-amz-date' => '20130524T000000Z',
    ], $empty, $key, $secret, 'us-east-1', '20130524T000000Z');
    ok(str_ends_with($auth, 'Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7'), 'List objects: ' . $auth);
});

test('retention: grandfather-father-son', function (): void {
    $items = [];
    $start = strtotime('2026-01-01 03:00:00');
    for ($d = 0; $d < 120; $d++) {
        $items['b' . $d] = $start + $d * 86400;
    }
    $keep = shield_retention_keep($items, 7, 4, 3);
    for ($d = 113; $d < 120; $d++) {
        ok(in_array('b' . $d, $keep, true), "daily b{$d}");
    }
    ok(count($keep) <= 7 + 4 + 3, 'at most daily+weekly+monthly, got ' . count($keep));
    ok(count($keep) >= 9, 'weekly/monthly add older backups, got ' . count($keep));
    $months = array_unique(array_map(static fn($n) => date('Y-m', $items[$n]), $keep));
    eq(3, count($months), 'three months covered');
    eq(['only'], shield_retention_keep(['only' => time()], 0, 0, 0), 'always keeps one');
    eq(shield_backup_time('2026-09-24_030001_daily'), strtotime('2026-09-24 03:00:01'), 'time from name');
});

test('ip lists: exact, CIDR v4 and v6, entries with notes', function (): void {
    ok(shield_ip_in_list('10.1.2.3', ['10.1.2.3']));
    ok(shield_ip_in_list('10.1.2.3', ['10.1.0.0/16']));
    ok(!shield_ip_in_list('10.2.2.3', ['10.1.0.0/16']));
    ok(shield_ip_in_list('192.168.1.130', ['192.168.1.128/25']));
    ok(!shield_ip_in_list('192.168.1.127', ['192.168.1.128/25']));
    ok(shield_ip_in_list('2001:db8::1', ['2001:db8::/32']));
    ok(!shield_ip_in_list('2001:db9::1', ['2001:db8::/32']));
    ok(shield_ip_in_list('1.2.3.4', [['ip' => '1.2.3.0/24', 'note' => 'office']]));
    ok(!shield_ip_in_list('1.2.3.4', ['2001:db8::/32', '', 'garbage']));
});

test('waf: exceptions match rule and path prefix', function (): void {
    $ex = [['rule' => 'xss_script', 'path' => '/wp-admin/post.php'], ['rule' => '*', 'path' => '/api/raw']];
    ok(shield_waf_excepted('xss_script', '/wp-admin/post.php', $ex));
    ok(!shield_waf_excepted('xss_script', '/index.php', $ex));
    ok(!shield_waf_excepted('sqli_union', '/wp-admin/post.php', $ex));
    ok(shield_waf_excepted('anything', '/api/raw/upload', $ex));
    ok(isset(shield_waf_rule_catalog()['exec_in_uploads']), 'catalog lists non-pattern rules');
    foreach (shield_waf_rules()['patterns'] as $id => [$re]) {
        ok(@preg_match($re, '') !== false, "valid regex {$id}");
    }
});

test('detect: WordPress, Laravel and Joomla credentials', function (): void {
    $root = $GLOBALS['t_tmp'] . '/sites';
    @mkdir($root . '/wp/wp-includes', 0777, true);
    file_put_contents($root . '/wp/wp-config.php', "<?php\ndefine( 'DB_NAME', 'wp_db' );\ndefine('DB_USER', \"wp_user\");\ndefine('DB_PASSWORD', 'p\\'ss');\ndefine('DB_HOST', 'localhost:3307');\n\$table_prefix = 'wp_';\n");
    eq('wordpress', shield_detect_platform($root . '/wp'));
    eq(['host' => 'localhost', 'port' => 3307, 'user' => 'wp_user', 'pass' => "p'ss", 'name' => 'wp_db'], shield_detect_db($root . '/wp', 'wordpress'));

    @mkdir($root . '/lara/public', 0777, true);
    file_put_contents($root . '/lara/artisan', '');
    file_put_contents($root . '/lara/.env', "APP_NAME=Test\nDB_HOST=127.0.0.1\nDB_DATABASE=\"lara db\"\nDB_USERNAME=lara # user\nDB_PASSWORD='s3cr#t'\n");
    eq('laravel', shield_detect_platform($root . '/lara/public'));
    eq($root . '/lara', shield_app_root($root . '/lara/public', 'laravel'));
    $db = shield_detect_db($root . '/lara/public', 'laravel');
    eq('lara db', $db['name'] ?? null, 'quoted value');
    eq('lara', $db['user'] ?? null, 'inline comment stripped');
    eq('s3cr#t', $db['pass'] ?? null, 'single quotes keep #');

    @mkdir($root . '/joomla/administrator', 0777, true);
    file_put_contents($root . '/joomla/configuration.php', "<?php class JConfig {\n public \$host = 'localhost';\n public \$user = 'j_user';\n public \$password = 'j_pass';\n public \$db = 'j_db';\n}");
    eq('joomla', shield_detect_platform($root . '/joomla'));
    eq('j_db', shield_detect_db($root . '/joomla', 'joomla')['name'] ?? null);

    @mkdir($root . '/plain', 0777, true);
    file_put_contents($root . '/plain/index.html', '<h1>hi</h1>');
    eq('static', shield_detect_platform($root . '/plain'));
    eq([], shield_detect_db($root . '/plain', 'static'));

    eq('example-com', shield_site_key('www.example.com', []));
    eq('example-com-2', shield_site_key('example.com', ['example-com' => []]));
});

test('settings: v1 configuration is normalized', function (): void {
    $v1 = [
        'alert_email' => 'me@example.com', 'mail_from' => 'shield@example.com', 'setup_key' => 'x',
        'backup' => ['keep' => 5, 'offsite' => ['type' => 'ftp', 'host' => 'ftp.example.com', 'user' => 'u', 'pass' => 'p', 'dir' => '/b', 'port' => 21, 'ssl' => true]],
        'waf' => ['mode' => 'block', 'allow_ips' => ['1.2.3.4'], 'alert_on_ban' => true],
        'sites' => ['shop' => ['url' => 'https://shop.example.com', 'hosts' => ['shop.example.com'], 'path' => '/home/u/shop/']],
    ];
    $c = shield_normalize(array_replace_recursive(shield_defaults(), $v1));
    eq('me@example.com', $c['notify']['email']);
    eq('shield@example.com', $c['notify']['mail_from']);
    eq(5, $c['backup']['keep_daily']);
    eq('ftp.example.com', $c['backup']['offsite']['ftp']['host']);
    ok(!isset($c['backup']['offsite']['host']), 'flat ftp keys removed');
    ok(!isset($c['setup_key']) && !isset($c['alert_email']), 'old keys removed');
    eq('1.2.3.4', $c['waf']['allow'][0]['ip'] ?? null);
    eq('/home/u/shop', $c['sites']['shop']['path'], 'trailing slash trimmed');
    eq('shop', $c['sites']['shop']['title'], 'title defaults to key');
    ok(is_array($c['sites']['shop']['waf_exceptions']), 'site defaults filled');
});

test('settings: saved file round-trips', function (): void {
    $s = shield_settings();
    $s['notify']['email'] = "a'b@example.com";
    $s['sites']['demo'] = ['path' => '/tmp/demo', 'title' => 'Demo "x"'];
    shield_settings_save($s);
    $c = shield_config(true);
    eq("a'b@example.com", $c['notify']['email']);
    eq('Demo "x"', $c['sites']['demo']['title']);
    ok(str_starts_with((string)file_get_contents(shield_path('settings.php')), '<?php'), 'stored as PHP');
    unset($s['sites']['demo']);
    shield_settings_save($s);
});

test('recovery codes: single use', function (): void {
    $admin = [];
    $codes = shield_recovery_codes_new($admin);
    eq(10, count($codes));
    ok(shield_recovery_code_use($admin, strtolower($codes[3])), 'case-insensitive');
    ok(!shield_recovery_code_use($admin, $codes[3]), 'used once');
    eq(9, count($admin['recovery']));
});

test('internal key: only for our own sites and dashboard, stable', function (): void {
    $s = shield_settings();
    $s['sites']['own'] = ['path' => '/tmp/own', 'title' => 'Own', 'url' => 'https://own.example', 'hosts' => ['own.example', 'www.own.example']];
    shield_settings_save($s);
    $k = shield_internal_key_for('https://own.example/.env');
    ok(is_string($k) && strlen($k) >= 32, 'own site gets the key');
    eq($k, shield_internal_key_for('https://WWW.own.example/'), 'alias host, same key');
    eq(null, shield_internal_key_for('https://api.github.com/repos/x'), 'never to other hosts');
    eq(null, shield_internal_key_for('not a url'), 'no host');
    ok(is_file(shield_path('waf/internal.key')), 'stored in data_dir/waf for the firewall');
    unset($s['sites']['own']);
    shield_settings_save($s);
});

test('url resolve: Location headers', function (): void {
    eq('https://a.example/login.php', shield_url_resolve('https://a.example/', '/login.php'));
    eq('https://b.example/x', shield_url_resolve('https://a.example/', 'https://b.example/x'));
    eq('https://c.example/y', shield_url_resolve('https://a.example/', '//c.example/y'));
    eq('https://a.example/dir/next.php', shield_url_resolve('https://a.example/dir/page.php?q=1', 'next.php'));
    eq('http://a.example:8080/z', shield_url_resolve('http://a.example:8080/q', '/z'));
});

test('notify: daily cap for non-critical alerts', function (): void {
    require_once dirname(__DIR__) . '/lib/notify.php';
    $qf = shield_path('cache/notify-quota.json');
    if (is_file($qf)) {
        unlink($qf);
    }
    eq(true, shield_notify_quota('ban', 0), 'no limit');
    eq(true, shield_notify_quota('ban', 2), '1st');
    eq(true, shield_notify_quota('changes', 2), '2nd');
    eq('capped', shield_notify_quota('login', 2), 'first over the cap: one "limit reached" notice');
    eq(false, shield_notify_quota('ban', 2), 'then silent');
    eq(true, shield_notify_quota('down', 2), 'critical always goes out');
    eq(true, shield_notify_quota('malware', 2), 'critical always goes out');
    eq(0, SHIELD_BAN_DIGEST['off']);
    eq(86400, SHIELD_BAN_DIGEST['daily']);
});
