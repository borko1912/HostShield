<?php
$j = shield_job_get((string)($_GET['id'] ?? ''));
if (!$j) {
    go('p=jobs');
}
$running = in_array($j['status'], ['queued', 'running'], true);
$title = shield_job_label((string)$j['type']);
?>
<p><a href="<?= e(url(['p' => 'jobs'])) ?>">← <?= e(__('Tasks')) ?></a></p>
<h1><?= e($title) ?> · <?= e($j['params']['site'] ?? '') ?> <span class="tag st-<?= e($j['status']) ?>"><?= e(['queued' => __('queued'), 'running' => __('running'), 'done' => __('done'), 'error' => __('error')][$j['status']] ?? $j['status']) ?></span></h1>
<?php if ($j['status'] === 'queued'): ?><p class="muted"><?= e(__('Waiting for the cron job (up to a minute)...')) ?></p><?php endif; ?>
<?php if ($running): ?><span data-refresh="3"></span><?php endif; ?>
<table class="log-table"><tbody><?php foreach ((array)$j['log'] as [$t, $m]): ?><tr><td class="muted nowrap"><?= e(date('H:i:s', (int)$t)) ?></td><td><?= e($m) ?></td></tr><?php endforeach; ?></tbody></table>
<?php if (!empty($j['error'])): ?><div class="alert err"><?= e($j['error']) ?></div><?php endif; ?>
<?php if ($j['status'] === 'done' && !empty($j['params']['site'])): ?>
    <p><a class="btn ghost" href="<?= e(url(['p' => 'site', 'site' => $j['params']['site'], 'tab' => ['backup' => 'backups', 'restore' => 'overview', 'integrity' => 'files', 'audit' => 'audit', 'offsite_fetch' => 'backups'][$j['type']] ?? 'overview'])) ?>"><?= e(__('Open the site')) ?></a></p>
<?php endif; ?>
