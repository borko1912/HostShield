<?php
/** @var array $cfg @var array $state @var int $lastCron @var array $admin */

$sites = shield_sites();
$events = shield_waf_events(5000, null, null, 1);
$today = array_filter($events, static fn($e) => $e['t'] >= strtotime('today'));
$blocked = array_filter($today, static fn($e) => $e['action'] !== 'logged');
$ips = array_count_values(array_column($today, 'ip'));
arsort($ips);
$rulesCount = [];
foreach ($today as $ev) {
    foreach ((array)$ev['rules'] as $r) {
        $rulesCount[$r] = ($rulesCount[$r] ?? 0) + 1;
    }
}
arsort($rulesCount);
$bans = shield_waf_bans();
$overall = shield_overall_score();
$daily = [];
foreach (shield_waf_daily(14) as $d => $row) {
    $daily[date('d.m', strtotime($d))] = [$row['blocked'], $row['logged']];
}

// Setup checklist.
$wafAll = $sites && !array_filter(array_keys($sites), static fn($k) => shield_site_waf_state(shield_site((string)$k)) !== 'on');
$backupAll = $sites && !array_filter(array_keys($sites), static fn($k) => !empty($sites[$k]['backup']) && !shield_list_backups((string)$k));
$steps = [
    [time() - $lastCron < 180, __('Cron job runs every minute'), '#cron'],
    [(bool)$sites, __('Sites added'), url(['p' => 'site_add'])],
    [$wafAll, __('Firewall enabled on every site'), $sites ? url(['p' => 'site', 'site' => array_key_first($sites)]) : url(['p' => 'site_add'])],
    [$backupAll, __('First backup of every site'), url(['p' => 'jobs'])],
    [shield_channel_configured('email') || shield_channel_configured('telegram') || shield_channel_configured('webhook'), __('Alerts configured (email, Telegram or chat)'), url(['p' => 'settings', 'tab' => 'notifications'])],
    [!empty($admin['totp']), __('Two-factor login enabled'), url(['p' => 'settings', 'tab' => 'security'])],
    [shield_offsite_enabled(), __('Off-site backup storage'), url(['p' => 'settings', 'tab' => 'backups'])],
    [($cfg['waf']['mode'] ?? 'log') === 'block', __('Firewall switched from Log to Block'), url(['p' => 'settings', 'tab' => 'firewall'])],
];
$done = count(array_filter($steps, static fn($s) => $s[0]));
?>
<div class="page-h">
    <h1><?= e(__('Overview')) ?></h1>
    <div class="toolbar">
        <?= post_button('audit_all', e(__('Run audit')), [], ['class' => 'ghost']) ?>
        <?= post_button('backup_all', e(__('Back up all sites')), [], ['class' => 'primary']) ?>
    </div>
</div>

<?php if (!empty($state['backup_running'])): ?>
    <div class="alert warn"><?= e(__('Nightly backup in progress (started %s).', shield_ago((int)$state['backup_running']))) ?></div>
<?php endif; ?>
<?php if (time() - $lastCron > 180): ?>
    <div class="alert err" id="cron">
        <b><?= e(__('The cron job is not running')) ?><?= $lastCron ? ' (' . e(__('last run %s', shield_ago($lastCron))) . ')' : '' ?>.</b>
        <?= e(__('Backups, scans and alerts do not run without it.')) ?>
        <?php require __DIR__ . '/../cron_help.php'; ?>
    </div>
<?php endif; ?>

<?php if ($done < count($steps)): ?>
<section class="panel checklist">
    <div class="panel-h"><h2><?= e(__('Setup checklist')) ?></h2><span class="muted"><?= $done ?>/<?= count($steps) ?></span></div>
    <progress value="<?= $done ?>" max="<?= count($steps) ?>"></progress>
    <ul>
        <?php foreach ($steps as [$ok, $label, $href]): ?>
            <li class="<?= $ok ? 'done' : '' ?>"><span class="tick" aria-hidden="true"><?= $ok ? '✓' : '' ?></span>
                <?= $ok ? e($label) : '<a href="' . e($href) . '">' . e($label) . '</a>' ?></li>
        <?php endforeach; ?>
    </ul>
</section>
<?php endif; ?>

<div class="stats">
    <div class="stat score">
        <?= grade_badge($overall, 'lg') ?>
        <div><span><?= e(__('Security grade')) ?></span><b><?= $overall ? (int)$overall['score'] . '/100' : '—' ?></b></div>
    </div>
    <div class="stat"><span><?= e(__('Attacks today')) ?></span><b><?= count($today) ?></b></div>
    <div class="stat"><span><?= e(__('Blocked')) ?></span><b><?= count($blocked) ?></b></div>
    <div class="stat"><span><?= e(__('Active bans')) ?></span><b><?= count($bans) ?></b></div>
    <div class="stat"><span><?= e(__('Last nightly backup')) ?></span><b class="sm"><?= e(shield_ago((int)($state['last_backup_run'] ?? 0))) ?></b>
        <?php if (isset($state['last_backup_ok'])): ?><em class="<?= $state['last_backup_ok'] ? 'ok' : 'bad' ?>"><?= e($state['last_backup_ok'] ? __('successful') : __('with errors')) ?></em><?php endif; ?></div>
</div>

<section class="panel">
    <div class="panel-h"><h2><?= e(__('Attacks, last 14 days')) ?></h2>
        <span class="legend"><i class="b"></i><?= e(__('blocked')) ?> <i class="l"></i><?= e(__('logged')) ?></span></div>
    <?= chart_bars($daily) ?>
    <div class="chart-x"><span><?= e((string)array_key_first($daily)) ?></span><span><?= e(__('today')) ?></span></div>
</section>

<h2><?= e(__('Sites')) ?></h2>
<?php if (!$sites): ?>
    <div class="empty"><p><?= e(__('No sites yet.')) ?></p><a class="btn primary" href="<?= e(url(['p' => 'site_add'])) ?>"><?= e(__('Find my sites')) ?></a></div>
<?php endif; ?>
<div class="cards">
<?php foreach ($sites as $k => $s):
    $b = shield_list_backups((string)$k);
    $up = shield_json_read(shield_path('uptime/' . $k . '.json'));
    $rep = shield_integrity_report((string)$k);
    $audit = shield_audit_result((string)$k);
    $hb = shield_path('waf/heartbeat/' . $k);
    $hbAge = is_file($hb) ? time() - (int)filemtime($hb) : null;
    $changes = count((array)($rep['added'] ?? [])) + count((array)($rep['modified'] ?? [])) + count((array)($rep['removed'] ?? []));
    $mal = count((array)($rep['malware'] ?? [])) + count((array)($rep['wp']['modified'] ?? [])) + count((array)($rep['wp']['unknown'] ?? []));
    $upOk = ($up['fails'] ?? 0) === 0 && !empty($up['checked']);
    $pct = shield_uptime_percent($up);
    ?>
    <a class="card" href="<?= e(url(['p' => 'site', 'site' => $k])) ?>">
        <div class="card-h">
            <div><b><?= e($s['title']) ?></b><div class="muted"><?= e(parse_url((string)$s['url'], PHP_URL_HOST) ?: $s['path']) ?> · <?= e(platform_label((string)$s['platform'])) ?></div></div>
            <?= grade_badge($audit) ?>
        </div>
        <ul class="kv">
            <li><span><?= e(__('Uptime')) ?></span><b class="<?= empty($up['checked']) ? '' : ($upOk ? 'ok' : 'bad') ?>"><?= empty($up['checked']) ? '—' : ($upOk ? e(($pct !== null ? $pct . '% · ' : '') . (int)$up['ms'] . ' ms') : e(__('DOWN (%d)', (int)$up['code']))) ?></b></li>
            <li><span><?= e(__('Firewall')) ?></span><b class="<?= $hbAge !== null && $hbAge < 86400 ? 'ok' : 'bad' ?>"><?= $hbAge === null ? e(__('not enabled')) : e(__('active · %s', shield_ago(time() - $hbAge))) ?></b></li>
            <li><span><?= e(__('Backups')) ?></span><b class="<?= $b ? '' : 'warn' ?>"><?= count($b) ?><?= $b ? ' · ' . e(shield_ago((int)$b[0]['created'])) : '' ?></b></li>
            <li><span><?= e(__('Files')) ?></span><b class="<?= $mal ? 'bad' : ($changes ? 'warn' : 'ok') ?>"><?= $mal ? e(__('%d suspicious!', $mal)) : ($changes ? e(__('%d changes', $changes)) : (empty($rep['checked']) ? '—' : e(__('clean')))) ?></b></li>
        </ul>
        <?= uptime_strip($up) ?>
        <?php if (!is_dir((string)$s['path'])): ?>
            <div class="card-err"><?= e(__('Folder does not exist: %s', $s['path'])) ?></div>
        <?php elseif (!empty($state['backup_errors'][$k])): ?>
            <div class="card-err"><?= e(__('Backup error: %s', (string)$state['backup_errors'][$k]['msg'])) ?></div>
        <?php endif; ?>
    </a>
<?php endforeach; ?>
    <?php if ($sites): ?><a class="card add" href="<?= e(url(['p' => 'site_add'])) ?>"><span>+</span><?= e(__('Add site')) ?></a><?php endif; ?>
</div>

<div class="grid2">
    <section>
        <h2><?= e(__('Top IP addresses today')) ?></h2>
        <table><thead><tr><th>IP</th><th><?= e(__('Events')) ?></th><th></th></tr></thead><tbody>
        <?php foreach (array_slice($ips, 0, 10, true) as $ip => $n): ?>
            <tr><td><a href="<?= e(url(['p' => 'firewall', 'ip' => $ip])) ?>"><?= e($ip) ?></a></td><td><?= (int)$n ?></td>
                <td class="actions"><?= post_button('list_add', e(__('Block')), ['list' => 'block', 'ip' => $ip, 'note' => __('from overview')], ['class' => 'xs danger']) ?></td></tr>
        <?php endforeach; ?>
        <?php if (!$ips): ?><tr><td colspan="3" class="muted"><?= e(__('No attacks today.')) ?></td></tr><?php endif; ?>
        </tbody></table>
    </section>
    <section>
        <h2><?= e(__('Attack types today')) ?></h2>
        <?php $cat = shield_waf_rule_catalog(); ?>
        <table><thead><tr><th><?= e(__('Rule')) ?></th><th><?= e(__('Count')) ?></th></tr></thead><tbody>
        <?php foreach (array_slice($rulesCount, 0, 10, true) as $r => $n): ?>
            <tr><td><span class="rule"><?= e($r) ?></span> <span class="muted"><?= e(isset($cat[$r]) ? __($cat[$r][1]) : '') ?></span></td><td><?= (int)$n ?></td></tr>
        <?php endforeach; ?>
        <?php if (!$rulesCount): ?><tr><td colspan="2" class="muted">—</td></tr><?php endif; ?>
        </tbody></table>
    </section>
</div>
