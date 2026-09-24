<?php
// Shows the exact cron command for this server. Included where the cron is missing.

$bins = shield_php_cli_binaries();
$best = $bins[0] ?? null;
$cronLog = shield_path('cron.log');
$worker = str_replace('\\', '/', shield_root()) . '/cron/worker.php';
?>
<div class="cron-help">
<?php if ($best): ?>
    <p><?= e(__('In your hosting panel open Cron Jobs, choose “every minute” (* * * * *) and paste this command:')) ?></p>
    <div class="copy"><code id="cron-cmd"><?= e($best['path'] . ' ' . $worker . ' >> ' . $cronLog . ' 2>&1') ?></code><button type="button" class="btn xs ghost" data-copy="cron-cmd"><?= e(__('Copy')) ?></button></div>
    <?php if (count($bins) > 1): ?>
        <p class="muted"><?= e(__('PHP versions found: %s', implode(', ', array_map(static fn($b) => $b['version'] . ' → ' . $b['path'], $bins)))) ?></p>
    <?php endif; ?>
<?php endif; ?>
    <p class="muted"><?= e($best ? __('If the command line PHP does not work, use the web variant instead:') : __('No PHP 8 command line found. Use this web cron in your hosting panel (every minute):')) ?></p>
    <div class="copy"><code id="cron-web"><?= e('curl -s "' . shield_dashboard_url() . '/?p=cron&token=' . shield_relay_token() . '" >/dev/null 2>&1') ?></code><button type="button" class="btn xs ghost" data-copy="cron-web"><?= e(__('Copy')) ?></button></div>
<?php if (is_file($cronLog) && filesize($cronLog) > 0):
    $h = fopen($cronLog, 'rb');
    fseek($h, max(0, filesize($cronLog) - 3000));
    $tail = (string)stream_get_contents($h);
    fclose($h); ?>
    <details><summary><?= e(__('Last cron output')) ?></summary><pre class="log"><?= e($tail) ?></pre></details>
<?php endif; ?>
</div>
