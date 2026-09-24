<?php
// Firewall: normal traffic must never be flagged (false positives break real sites).

function waf_req(array $o): array
{
    $uri = $o['uri'] ?? '/';
    return $o + [
        'method' => 'GET', 'uri' => $uri, 'path' => strtolower(rawurldecode((string)parse_url($uri, PHP_URL_PATH))),
        'ua' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36', 'referer' => '',
        'get' => [], 'post' => [], 'cookie' => [], 'body' => null, 'files' => [], 'script' => null,
    ];
}

function waf_hits(array $req, array $site = ['platform' => 'php', 'upload_dirs' => ['uploads']], array $waf = []): array
{
    $waf += ['block_exec_in_uploads' => true, 'wp_block_user_enum' => true, 'wp_block_xmlrpc' => false];
    return array_keys(shield_waf_inspect(waf_req($req), $waf, $site)['hits']);
}

test('waf: normal requests pass', function (): void {
    $benign = [
        ['uri' => '/'],
        ['uri' => '/products?category=shoes&sort=price_asc&page=2', 'get' => ['category' => 'shoes', 'sort' => 'price_asc', 'page' => '2']],
        ['uri' => '/search?q=select+a+union+member', 'get' => ['q' => 'select a union member']],
        ['get' => ['q' => "Tom's Diner"]],
        ['get' => ['q' => 'rock & roll']],
        ['get' => ['q' => 'Как да изберем обувки? 50% отстъпка']],
        ['get' => ['email' => 'john.o\'neil+news@example.com']],
        ['get' => ['utm_source' => 'google', 'utm_medium' => 'cpc', 'gclid' => 'Cj0KCQjw-abc_123']],
        ['get' => ['redirect_to' => 'https://example.com/account/orders']],
        ['get' => ['date_from' => '2026-01-01', 'date_to' => '2026-12-31']],
        ['method' => 'POST', 'post' => ['name' => 'Ivan Petrov', 'message' => "Hello,\nI would like to order 3 items. Please call me at +359 88 123 4567.\nThanks!"]],
        ['method' => 'POST', 'post' => ['comment' => 'The price is < 100 and > 50, isn\'t it? I\'d say "yes" or "no".']],
        ['method' => 'POST', 'post' => ['address' => 'ul. "Aleksandrovska" 12, et. 3; ap. 4']],
        ['method' => 'POST', 'post' => ['bio' => 'I love C#, F# and SQL -- especially joins.']],
        ['method' => 'POST', 'post' => ['note' => 'Select the size, then choose a color from the drop-down.']],
        ['method' => 'POST', 'post' => ['log' => 'admin', 'pwd' => 'correct horse battery staple', 'rememberme' => 'forever']],
        ['method' => 'POST', 'post' => ['content' => '<p>Welcome to our <strong>new</strong> shop! <a href="/sale">See the sale</a>.</p><img src="/a.jpg" alt="shoes">']],
        ['method' => 'POST', 'body' => ['items' => [['sku' => 'A-1', 'qty' => 2], ['sku' => 'B-7', 'qty' => 1]], 'coupon' => 'AUTUMN10']],
        ['method' => 'POST', 'body' => ['query' => 'query { product(id: 5) { name price } }']],
        ['cookie' => ['_ga' => 'GA1.2.123456789.1700000000', 'cart' => '{"items":[1,2,3]}', 'lang' => 'bg']],
        ['cookie' => ['wordpress_logged_in_abc' => 'admin|1700000000|token|hash']],
        ['uri' => '/assets/themes/default/style.css'],
        ['uri' => '/blog/2026/09/how-to-select-the-right-plan/'],
        ['uri' => '/api/v1/orders/1234', 'method' => 'PUT', 'body' => ['status' => 'shipped']],
        ['get' => ['text' => 'Price: $10 (incl. VAT); delivery: 2-3 days']],
        ['get' => ['lookup' => 'www.example.com']],
        ['files' => [['photo.jpg', ''], ['invoice.pdf', '']], 'method' => 'POST'],
    ];
    foreach ($benign as $i => $req) {
        eq([], waf_hits($req), 'request #' . $i . ' ' . json_encode($req, JSON_UNESCAPED_UNICODE));
    }
});

test('waf: WordPress paths are normal on WordPress sites only', function (): void {
    $wp = ['platform' => 'wordpress', 'upload_dirs' => ['wp-content/uploads']];
    eq([], waf_hits(['uri' => '/wp-login.php'], $wp));
    eq([], waf_hits(['uri' => '/wp-admin/edit.php?post_type=page', 'get' => ['post_type' => 'page']], $wp));
    eq(['probe'], waf_hits(['uri' => '/wp-login.php']), 'probe on a non-WordPress site');
});

test('waf: login detection feeds brute-force limits', function (): void {
    $r = shield_waf_inspect(waf_req(['method' => 'POST', 'post' => ['log' => 'a', 'pwd' => 'b']]), [], []);
    ok($r['is_login']);
    $r = shield_waf_inspect(waf_req(['method' => 'POST', 'post' => ['name' => 'a']]), [], []);
    ok(!$r['is_login']);
});

test('waf: scripts inside upload folders are flagged, others not', function (): void {
    eq(['exec_in_uploads'], waf_hits(['uri' => '/uploads/2026/x.php', 'script' => 'uploads/2026/x.php']));
    eq([], waf_hits(['uri' => '/index.php', 'script' => 'index.php']));
    eq([], waf_hits(['uri' => '/uploads/x.php', 'script' => 'uploads/x.php'], ['upload_dirs' => ['uploads']], ['block_exec_in_uploads' => false]));
});

test('waf: exceptions and disabled rules silence a rule', function (): void {
    $site = ['platform' => 'php', 'upload_dirs' => ['uploads'], 'waf_exceptions' => [['rule' => 'exec_in_uploads', 'path' => '/uploads/tools/']]];
    eq([], waf_hits(['uri' => '/uploads/tools/run.php', 'script' => 'uploads/tools/run.php'], $site));
    eq(['exec_in_uploads'], waf_hits(['uri' => '/uploads/other/run.php', 'script' => 'uploads/other/run.php'], $site));
    $site = ['platform' => 'php', 'upload_dirs' => ['uploads'], 'waf_disabled_rules' => ['probe']];
    eq([], waf_hits(['uri' => '/wp-login.php'], $site));
});
