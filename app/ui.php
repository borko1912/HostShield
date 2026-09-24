<?php
declare(strict_types=1);

// Small view helpers for the dashboard.

function e(mixed $v): string
{
    return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
}

function flash(?string $msg = null, string $type = 'ok'): array
{
    shield_session_start();
    if ($msg !== null) {
        $_SESSION['flash'][] = [$type, $msg];
        return [];
    }
    $f = (array)($_SESSION['flash'] ?? []);
    unset($_SESSION['flash']);
    return $f;
}

function go(string $query = ''): never
{
    header('Location: ./' . ($query !== '' ? '?' . $query : ''));
    exit;
}

function url(array $q): string
{
    return '?' . http_build_query($q);
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . e(shield_csrf()) . '">';
}

/** A one-button POST form. $opts: class, confirm, fields (name => value), title */
function post_button(string $action, string $label, array $fields = [], array $opts = []): string
{
    $h = '<form method="post" class="inline"' . (!empty($opts['confirm']) ? ' data-confirm="' . e($opts['confirm']) . '"' : '') . '>' . csrf_field()
        . '<input type="hidden" name="action" value="' . e($action) . '">';
    foreach ($fields as $k => $v) {
        $h .= '<input type="hidden" name="' . e($k) . '" value="' . e($v) . '">';
    }
    return $h . '<button class="btn ' . e($opts['class'] ?? '') . '"' . (!empty($opts['title']) ? ' title="' . e($opts['title']) . '"' : '') . '>' . $label . '</button></form>';
}

function site_key_param(string $name = 'site'): string
{
    $k = (string)($_POST[$name] ?? $_GET[$name] ?? '');
    if (!isset(shield_sites()[$k])) {
        http_response_code(404);
        exit(e(__('Unknown site')));
    }
    return $k;
}

function badge(string $text, string $kind = ''): string
{
    return '<span class="badge ' . e($kind) . '">' . e($text) . '</span>';
}

function grade_badge(?array $a, string $size = ''): string
{
    if (!$a || !isset($a['grade'])) {
        return '<span class="grade none ' . e($size) . '" title="' . e(__('Not audited yet')) . '">–</span>';
    }
    return '<span class="grade g' . e($a['grade']) . ' ' . e($size) . '" title="' . e($a['score'] . '/100') . '">' . e($a['grade']) . '</span>';
}

function severity_badge(string $sev): string
{
    $labels = ['critical' => __('critical'), 'high' => __('high'), 'medium' => __('medium'), 'low' => __('low'), 'info' => __('info')];
    return '<span class="sev ' . e($sev) . '">' . e($labels[$sev] ?? $sev) . '</span>';
}

function platform_label(string $p): string
{
    require_once dirname(__DIR__) . '/lib/detect.php';
    return SHIELD_PLATFORMS[$p] ?? $p;
}

/** Form field helpers. $name uses bracket notation, e.g. waf[mode]. */
function field_text(string $name, string $label, mixed $value, string $help = '', array $attr = []): string
{
    $a = '';
    foreach ($attr as $k => $v) {
        $a .= ' ' . e($k) . ($v === true ? '' : '="' . e($v) . '"');
    }
    return '<label class="field"><span>' . e($label) . '</span><input name="' . e($name) . '" value="' . e($value) . '"' . $a . '>'
        . ($help !== '' ? '<small>' . $help . '</small>' : '') . '</label>';
}

/** Password/secret field: left empty keeps the stored value. */
function field_secret(string $name, string $label, string $current, string $help = ''): string
{
    $ph = $current !== '' ? __('•••••• saved — leave empty to keep') : '';
    return '<label class="field"><span>' . e($label) . '</span><input type="password" name="' . e($name) . '" placeholder="' . e($ph) . '" autocomplete="new-password">'
        . ($help !== '' ? '<small>' . $help . '</small>' : '') . '</label>';
}

function field_textarea(string $name, string $label, array|string $value, string $help = '', int $rows = 4): string
{
    $v = is_array($value) ? implode("\n", $value) : $value;
    return '<label class="field"><span>' . e($label) . '</span><textarea name="' . e($name) . '" rows="' . $rows . '">' . e($v) . '</textarea>'
        . ($help !== '' ? '<small>' . $help . '</small>' : '') . '</label>';
}

function field_select(string $name, string $label, mixed $value, array $options, string $help = ''): string
{
    $h = '<label class="field"><span>' . e($label) . '</span><select name="' . e($name) . '">';
    foreach ($options as $k => $l) {
        $h .= '<option value="' . e($k) . '"' . ((string)$k === (string)$value ? ' selected' : '') . '>' . e($l) . '</option>';
    }
    return $h . '</select>' . ($help !== '' ? '<small>' . $help . '</small>' : '') . '</label>';
}

function field_check(string $name, string $label, bool $checked, string $help = ''): string
{
    return '<label class="check"><input type="hidden" name="' . e($name) . '" value="0"><input type="checkbox" name="' . e($name) . '" value="1"' . ($checked ? ' checked' : '') . '>'
        . '<span>' . e($label) . ($help !== '' ? '<small>' . $help . '</small>' : '') . '</span></label>';
}

/** Lines of a textarea as a clean list. */
function lines(mixed $v): array
{
    return array_values(array_filter(array_map('trim', preg_split('/[\r\n,]+/', (string)$v)), 'strlen'));
}

/** Tiny inline SVG bar chart: $data = [label => [blocked, logged]]. */
function chart_bars(array $data): string
{
    $max = 1;
    foreach ($data as [$b, $l]) {
        $max = max($max, $b + $l);
    }
    $n = count($data);
    $w = 100 / max(1, $n);
    $svg = '<svg class="chart" viewBox="0 0 100 40" preserveAspectRatio="none" role="img" aria-label="' . e(__('Attacks per day')) . '">';
    $i = 0;
    foreach ($data as $label => [$b, $l]) {
        $x = $i * $w + $w * 0.15;
        $bw = $w * 0.7;
        $hb = 38 * $b / $max;
        $hl = 38 * $l / $max;
        $title = e($label . ': ' . __('%d blocked, %d logged', $b, $l));
        $svg .= '<g><title>' . $title . '</title>'
            . '<rect x="' . round($x, 2) . '" y="' . round(40 - $hb, 2) . '" width="' . round($bw, 2) . '" height="' . round(max($hb, 0), 2) . '" class="b"/>'
            . '<rect x="' . round($x, 2) . '" y="' . round(40 - $hb - $hl, 2) . '" width="' . round($bw, 2) . '" height="' . round(max($hl, 0), 2) . '" class="l"/></g>';
        $i++;
    }
    return $svg . '</svg>';
}

/** Uptime history as a strip of small bars (last 24 h). */
function uptime_strip(array $st): string
{
    $rows = array_slice((array)($st['history'] ?? []), -96);
    if (!$rows) {
        return '';
    }
    $h = '<div class="strip" aria-hidden="true">';
    foreach ($rows as [$t, $ok, $ms]) {
        $h .= '<i class="' . ($ok ? 'up' : 'down') . '" title="' . e(date('H:i', (int)$t) . ' · ' . ($ok ? (int)$ms . ' ms' : __('down'))) . '"></i>';
    }
    return $h . '</div>';
}

function render_events(array $events, bool $withActions = true): void
{
    if (!$events) {
        echo '<p class="muted">' . e(__('No events.')) . '</p>';
        return;
    }
    $cat = shield_waf_rule_catalog();
    echo '<div class="scroll"><table class="events"><thead><tr><th>' . e(__('Time')) . '</th><th>' . e(__('Site')) . '</th><th>IP</th><th>' . e(__('Request')) . '</th><th>' . e(__('Rules')) . '</th><th>' . e(__('Action')) . '</th></tr></thead><tbody>';
    foreach ($events as $ev) {
        $cls = $ev['action'] === 'logged' ? 'warn' : 'bad';
        $rules = '';
        foreach ((array)$ev['rules'] as $r) {
            $where = (string)($ev['where'][$r] ?? '');
            $desc = isset($cat[$r]) ? __($cat[$r][1]) : $r;
            $rules .= '<div><span class="rule" title="' . e($desc) . '">' . e($r) . '</span>' . ($where !== '' ? ' <span class="muted">' . e(mb_substr($where, 0, 60)) . '</span>' : '');
            if ($withActions && isset(shield_sites()[$ev['site']]) && !in_array($r, ['rate_limit', 'blocklist', 'login_bruteforce'], true)) {
                $path = strtolower((string)parse_url((string)$ev['uri'], PHP_URL_PATH));
                $rules .= ' ' . post_button('waf_exception', __('Not an attack'), ['site' => $ev['site'], 'rule' => $r, 'path' => $path],
                    ['class' => 'xs ghost', 'confirm' => __('Stop checking rule %s on %s for this site?', $r, $path), 'title' => __('Allow this rule on this path (false positive)')]);
            }
            $rules .= '</div>';
        }
        echo '<tr><td class="nowrap">' . e(date('d.m H:i:s', (int)$ev['t'])) . '</td><td>' . e($ev['site']) . '</td>'
            . '<td><a href="' . e(url(['p' => 'firewall', 'ip' => $ev['ip']])) . '">' . e($ev['ip']) . '</a></td>'
            . '<td class="uri"><b>' . e($ev['m']) . '</b> ' . e(mb_substr((string)$ev['uri'], 0, 140)) . '<div class="muted">' . e(mb_substr((string)$ev['ua'], 0, 90)) . '</div></td>'
            . '<td>' . $rules . '</td><td class="' . $cls . '">' . e(['logged' => __('logged'), 'blocked' => __('blocked'), 'banned' => __('banned')][$ev['action']] ?? $ev['action'])
            . '<div class="muted mono">' . e($ev['id']) . '</div></td></tr>';
    }
    echo '</tbody></table></div>';
}

function render_head(string $title): void
{
    ?><!doctype html><html lang="<?= e(shield_lang()) ?>"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex,nofollow"><title><?= e($title) ?> · HostShield</title>
    <link rel="icon" href="assets/logo.svg" type="image/svg+xml">
    <link rel="stylesheet" href="assets/app.css?v=<?= e(SHIELD_VERSION) ?>"><script src="assets/app.js?v=<?= e(SHIELD_VERSION) ?>" defer></script></head><?php
}

function render_layout(string $p, string $title, string $content, array $flashes): void
{
    render_head($title);
    $nav = [
        'home' => ['M3 12l9-8 9 8M5 10v10h14V10', __('Overview')],
        'firewall' => ['M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z', __('Firewall')],
        'jobs' => ['M4 6h16M4 12h16M4 18h10', __('Tasks')],
        'settings' => ['M12 8a4 4 0 100 8 4 4 0 000-8zM4 12h2M18 12h2M12 4v2M12 18v2', __('Settings')],
        'about' => ['M12 21s-7-4.5-7-10a4 4 0 017-2.6A4 4 0 0119 11c0 5.5-7 10-7 10z', __('Support')],
    ];
    $active = match ($p) {
        'site', 'site_add' => 'home',
        'job' => 'jobs',
        default => $p,
    };
    ?><body>
    <a class="skip" href="#main"><?= e(__('Skip to content')) ?></a>
    <aside class="side">
        <a class="brand" href="./"><img src="assets/logo.svg" alt="" width="28" height="28"><span>HostShield</span></a>
        <nav>
        <?php foreach ($nav as $k => [$icon, $label]): ?>
            <a href="<?= e(url(['p' => $k])) ?>" class="<?= $active === $k ? 'on' : '' ?>"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="<?= e($icon) ?>"/></svg><span><?= e($label) ?></span></a>
        <?php endforeach; ?>
        </nav>
        <div class="side-sites">
            <div class="side-h"><?= e(__('Sites')) ?> <a href="<?= e(url(['p' => 'site_add'])) ?>" title="<?= e(__('Add site')) ?>">+</a></div>
            <?php foreach (shield_sites() as $k => $s): ?>
                <a href="<?= e(url(['p' => 'site', 'site' => $k])) ?>" class="<?= ($_GET['site'] ?? '') === $k ? 'on' : '' ?>"><?= e($s['title']) ?></a>
            <?php endforeach; ?>
        </div>
        <div class="side-foot">
            <?= post_button('logout', e(__('Log out')), [], ['class' => 'ghost sm']) ?>
        </div>
    </aside>
    <main id="main">
        <?php if ($rel = shield_update_available()): ?>
            <div class="alert info"><?= e(__('HostShield %s is available (you have %s).', $rel['version'], SHIELD_VERSION)) ?> <a href="<?= e($rel['url']) ?>" target="_blank" rel="noopener"><?= e(__('What\'s new')) ?></a></div>
        <?php endif; ?>
        <?php foreach ($flashes as [$t, $m]): ?><div class="alert <?= e($t) ?>"><?= e($m) ?></div><?php endforeach; ?>
        <?= $content ?>
        <footer class="muted">HostShield <?= e(SHIELD_VERSION) ?> · <?= e(date('d.m.Y H:i')) ?> ·
            <a href="https://github.com/<?= e(SHIELD_REPO) ?>" target="_blank" rel="noopener">GitHub</a> ·
            <a href="<?= e(url(['p' => 'about'])) ?>">♥ <?= e(__('Support the project')) ?></a></footer>
    </main>
    </body></html><?php
}

function render_auth(string $title, string $err, callable $body): void
{
    render_head($title);
    ?><body class="auth"><form method="post" class="auth-box">
        <div class="brand"><img src="assets/logo.svg" alt="" width="34" height="34"><span>HostShield</span></div>
        <h1><?= e($title) ?></h1>
        <?php if ($err): ?><div class="alert err"><?= e($err) ?></div><?php endif; ?>
        <?= csrf_field() ?>
        <?php $body(); ?>
    </form></body></html><?php
}
