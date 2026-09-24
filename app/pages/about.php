<?php
/** @var array $cfg @var array $state @var int $lastCron */
$exts = ['zip' => class_exists('ZipArchive'), 'mysqli' => class_exists('mysqli'), 'curl' => function_exists('curl_init'),
    'openssl' => function_exists('openssl_x509_parse'), 'ftp' => function_exists('ftp_connect'), 'mbstring' => function_exists('mb_substr'),
    'simplexml' => function_exists('simplexml_load_string'), 'apcu' => function_exists('apcu_inc')];
$backupBytes = 0;
foreach (array_keys(shield_sites()) as $k) {
    foreach (shield_list_backups((string)$k) as $m) {
        $backupBytes += (int)($m['total_size'] ?? 0);
    }
}
$free = @disk_free_space(shield_path());
$rel = shield_update_check();
?>
<div class="page-h"><h1><?= e(__('Support HostShield')) ?></h1></div>

<section class="panel hero">
    <p><?= e(__('HostShield is free and open source. If it saved your site — or your weekend — please consider supporting its development. Donations pay for testing on more hosting providers and for new features.')) ?></p>
    <div class="toolbar">
        <?php foreach (SHIELD_FUNDING as $label => $link): ?>
            <a class="btn primary" href="<?= e($link) ?>" target="_blank" rel="noopener">♥ <?= e($label) ?></a>
        <?php endforeach; ?>
        <a class="btn ghost" href="https://github.com/<?= e(SHIELD_REPO) ?>" target="_blank" rel="noopener">★ <?= e(__('Star on GitHub')) ?></a>
    </div>
    <p class="muted"><?= e(__('Found a bug or a false positive? Open an issue on GitHub — include the event id from the firewall log.')) ?>
        <a href="https://github.com/<?= e(SHIELD_REPO) ?>/issues" target="_blank" rel="noopener"><?= e(__('Issues')) ?></a> ·
        <a href="https://github.com/<?= e(SHIELD_REPO) ?>#readme" target="_blank" rel="noopener"><?= e(__('Documentation')) ?></a></p>
</section>

<div class="grid2">
    <section class="panel">
        <h2><?= e(__('Version')) ?></h2>
        <ul class="kv">
            <li><span>HostShield</span><b><?= e(SHIELD_VERSION) ?></b></li>
            <li><span><?= e(__('Latest release')) ?></span><b class="<?= $rel && version_compare($rel['version'], SHIELD_VERSION, '>') ? 'warn' : '' ?>"><?= $rel ? '<a href="' . e($rel['url']) . '" target="_blank" rel="noopener">' . e($rel['version']) . '</a>' : '—' ?></b></li>
        </ul>
        <?= post_button('update_check', e(__('Check now')), [], ['class' => 'ghost sm']) ?>
        <p class="muted"><?= e(__('To update: download the new release and upload it over the old files. Your settings and backups live in the data folder and are not touched.')) ?></p>
    </section>
    <section class="panel">
        <h2><?= e(__('System')) ?></h2>
        <ul class="kv">
            <li><span>PHP</span><b><?= e(PHP_VERSION . ' (' . PHP_SAPI . ')') ?></b></li>
            <li><span><?= e(__('Cron')) ?></span><b class="<?= time() - $lastCron < 180 ? 'ok' : 'bad' ?>"><?= e($lastCron ? shield_ago($lastCron) . ' · PHP ' . ($state['worker_php'] ?? '?') . ' · ' . ($state['worker_sapi'] ?? '') : __('never')) ?></b></li>
            <li><span><?= e(__('Extensions')) ?></span><b><?php foreach ($exts as $x => $ok): ?><span class="<?= $ok ? 'ok' : ($x === 'apcu' || $x === 'ftp' ? 'muted' : 'bad') ?>"><?= e($x) ?></span> <?php endforeach; ?></b></li>
            <li><span><?= e(__('Firewall loads via')) ?></span><b><?= e(shield_waf_method() === 'htaccess' ? '.htaccess (mod_php)' : (ini_get('user_ini.filename') ?: '.user.ini')) ?></b></li>
            <li><span><?= e(__('Data folder')) ?></span><b><code><?= e(shield_path()) ?></code></b></li>
            <li><span><?= e(__('Backups use')) ?></span><b><?= e(shield_human_size((float)$backupBytes)) ?></b></li>
            <li><span><?= e(__('Free disk space')) ?></span><b class="<?= $free !== false && $free < 2 * $backupBytes / max(1, count(shield_sites())) ? 'warn' : '' ?>"><?= $free !== false ? e(shield_human_size((float)$free)) : '—' ?></b></li>
            <li><span>memory_limit / max_execution_time</span><b><?= e(ini_get('memory_limit') . ' / ' . ini_get('max_execution_time') . 's') ?></b></li>
        </ul>
    </section>
</div>

<section class="panel">
    <h2><?= e(__('Cron job')) ?></h2>
    <?php require __DIR__ . '/../cron_help.php'; ?>
</section>
