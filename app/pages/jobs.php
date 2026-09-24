<?php
/** @var int $lastCron */
$jobs = shield_jobs(100);
?>
<div class="page-h"><h1><?= e(__('Tasks')) ?></h1></div>
<?php if (time() - $lastCron > 180 && array_filter($jobs, static fn($j) => $j['status'] === 'queued')): ?>
    <div class="alert warn"><?= e(__('The cron job does not seem to run, so tasks are waiting.')) ?> <a href="./#cron"><?= e(__('How to fix')) ?></a></div>
<?php endif; ?>
<?php if (array_filter($jobs, static fn($j) => in_array($j['status'], ['queued', 'running'], true))): ?><span data-refresh="5"></span><?php endif; ?>
<div class="scroll"><table><thead><tr><th><?= e(__('When')) ?></th><th><?= e(__('Task')) ?></th><th><?= e(__('Site')) ?></th><th><?= e(__('Status')) ?></th><th></th></tr></thead><tbody>
<?php foreach ($jobs as $j): ?>
    <tr><td class="nowrap"><?= e(date('d.m H:i:s', (int)$j['created'])) ?></td>
        <td><?= e(shield_job_label((string)$j['type'])) ?><?php if ($j['type'] === 'restore'): ?><div class="muted"><?= e($j['params']['backup']) ?> · <?= e($j['params']['scope']) ?></div><?php endif; ?></td>
        <td><?= e($j['params']['site'] ?? '') ?></td>
        <td><span class="tag st-<?= e($j['status']) ?>"><?= e(['queued' => __('queued'), 'running' => __('running'), 'done' => __('done'), 'error' => __('error')][$j['status']] ?? $j['status']) ?></span></td>
        <td><a href="<?= e(url(['p' => 'job', 'id' => $j['id']])) ?>"><?= e(__('details')) ?></a></td></tr>
<?php endforeach; ?>
<?php if (!$jobs): ?><tr><td colspan="5" class="muted"><?= e(__('No tasks yet.')) ?></td></tr><?php endif; ?>
</tbody></table></div>
