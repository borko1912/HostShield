<?php
$existing = array_column(shield_sites(), 'path');
$found = array_values(array_filter(shield_discover_sites(), static fn($d) => !in_array($d['path'], $existing, true)));
?>
<div class="page-h"><h1><?= e(__('Add sites')) ?></h1></div>
<form method="post" class="form">
    <?= csrf_field() ?><input type="hidden" name="action" value="site_add">
    <section class="panel">
        <h2><?= e(__('Found in this hosting account')) ?></h2>
        <?php if ($found): ?>
            <p class="muted"><?= e(__('HostShield looked for web folders in %s. Database access is read from each application\'s own config file.', shield_guess_home())) ?></p>
            <table><thead><tr><th><input type="checkbox" data-check-all="paths[]" aria-label="<?= e(__('Select all')) ?>" checked></th><th><?= e(__('Site')) ?></th><th><?= e(__('Platform')) ?></th><th><?= e(__('Database')) ?></th></tr></thead><tbody>
            <?php foreach ($found as $d): ?>
                <tr><td><input type="checkbox" name="paths[]" value="<?= e($d['path']) ?>" checked></td>
                    <td><b><?= e($d['domain'] ?: basename($d['path'])) ?></b><div class="muted"><code><?= e($d['path']) ?></code></div></td>
                    <td><?= e(platform_label($d['platform'])) ?></td>
                    <td><?= $d['db'] ? '<span class="ok">✓ ' . e($d['db']['name']) . '</span>' : '<span class="muted">' . e(__('not found — add it later')) . '</span>' ?></td></tr>
            <?php endforeach; ?>
            </tbody></table>
        <?php else: ?>
            <p class="muted"><?= e(__('No new web folders found automatically. Add one by path below.')) ?></p>
        <?php endif; ?>
    </section>
    <section class="panel">
        <h2><?= e(__('Add by path')) ?></h2>
        <div class="row2">
            <?= field_text('manual_path', __('Folder'), '', e(__('Full path, e.g. /home/user/example.com')), ['placeholder' => shield_guess_home() . '/example.com']) ?>
            <?= field_text('manual_domain', __('Domain'), '', '', ['placeholder' => 'example.com']) ?>
        </div>
    </section>
    <button class="btn primary"><?= e(__('Add selected sites')) ?></button>
</form>
