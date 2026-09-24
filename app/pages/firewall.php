<?php
/** @var array $cfg */
$ipF = isset($_GET['ip']) && filter_var($_GET['ip'], FILTER_VALIDATE_IP) ? (string)$_GET['ip'] : null;
$siteF = isset($_GET['site']) && isset(shield_sites()[$_GET['site']]) ? (string)$_GET['site'] : null;
$bans = shield_waf_bans();
$w = (array)$cfg['waf'];
?>
<div class="page-h">
    <h1><?= e(__('Firewall')) ?> <small class="muted"><?= e(__('mode')) ?>: <b><?= e($w['mode'] === 'block' ? __('block') : __('log only')) ?></b></small></h1>
    <a class="btn ghost" href="<?= e(url(['p' => 'settings', 'tab' => 'firewall'])) ?>"><?= e(__('Firewall settings')) ?></a>
</div>
<?php if ($w['mode'] !== 'block'): ?>
    <div class="alert info"><?= e(__('Log-only mode: attacks are recorded but not stopped. Watch the events for a few days, mark false positives with “Not an attack”, then switch to Block in the settings.')) ?></div>
<?php endif; ?>

<div class="grid2">
    <section>
        <h2><?= e(__('Active bans')) ?> <small class="muted"><?= count($bans) ?></small></h2>
        <table><thead><tr><th>IP</th><th><?= e(__('Until')) ?></th><th><?= e(__('Reason')) ?></th><th></th></tr></thead><tbody>
        <?php foreach (array_slice($bans, 0, 100) as $b): ?>
            <tr><td><a href="<?= e(url(['p' => 'firewall', 'ip' => $b['ip']])) ?>"><?= e($b['ip']) ?></a><div class="muted"><?= e($b['site'] ?? '') ?></div></td>
                <td class="nowrap"><?= e(date('d.m H:i', (int)$b['until'])) ?></td><td class="muted"><?= e(implode(', ', (array)($b['rules'] ?? []))) ?></td>
                <td class="actions"><?= post_button('unban', e(__('Unban')), ['file' => $b['file']], ['class' => 'xs ghost']) ?></td></tr>
        <?php endforeach; ?>
        <?php if (!$bans): ?><tr><td colspan="4" class="muted"><?= e(__('None.')) ?></td></tr><?php endif; ?>
        </tbody></table>
    </section>
    <section>
        <h2><?= e(__('Allow and block lists')) ?></h2>
        <form method="post" class="row">
            <?= csrf_field() ?><input type="hidden" name="action" value="list_add">
            <input name="ip" placeholder="<?= e(__('IP or 1.2.3.0/24')) ?>" aria-label="IP" required>
            <input name="note" placeholder="<?= e(__('note (e.g. office)')) ?>" aria-label="<?= e(__('Note')) ?>">
            <select name="list" aria-label="<?= e(__('List')) ?>"><option value="allow"><?= e(__('Always allow')) ?></option><option value="block"><?= e(__('Always block')) ?></option></select>
            <button class="btn"><?= e(__('Add')) ?></button>
        </form>
        <p class="muted"><?= e(__('Your IP now: %s', shield_client_ip())) ?></p>
        <table><thead><tr><th>IP</th><th><?= e(__('List')) ?></th><th><?= e(__('Note')) ?></th><th></th></tr></thead><tbody>
        <?php foreach (['allow', 'block'] as $which): foreach ((array)$w[$which] as $x): ?>
            <tr><td><?= e($x['ip']) ?></td><td class="<?= $which === 'allow' ? 'ok' : 'bad' ?>"><?= e($which === 'allow' ? __('allowed') : __('blocked')) ?></td><td class="muted"><?= e($x['note'] ?? '') ?></td>
                <td class="actions"><?= post_button('list_remove', e(__('Remove')), ['ip' => $x['ip']], ['class' => 'xs ghost']) ?></td></tr>
        <?php endforeach; endforeach; ?>
        <?php if (!$w['allow'] && !$w['block']): ?><tr><td colspan="4" class="muted"><?= e(__('Empty.')) ?></td></tr><?php endif; ?>
        </tbody></table>
    </section>
</div>

<div class="page-h">
    <h2><?= $ipF ? e(__('Events for %s', $ipF)) : e(__('Events, last 48 hours')) ?></h2>
    <form method="get" class="row compact">
        <input type="hidden" name="p" value="firewall">
        <select name="site" aria-label="<?= e(__('Site')) ?>" data-autosubmit><option value=""><?= e(__('All sites')) ?></option>
            <?php foreach (shield_sites() as $sk => $ss): ?><option value="<?= e($sk) ?>"<?= $siteF === $sk ? ' selected' : '' ?>><?= e($ss['title']) ?></option><?php endforeach; ?></select>
        <?php if ($ipF || $siteF): ?><a class="btn ghost sm" href="<?= e(url(['p' => 'firewall'])) ?>"><?= e(__('Clear filter')) ?></a><?php endif; ?>
    </form>
</div>
<?php render_events(shield_waf_events(300, $ipF, $siteF, $ipF ? 14 : 2)); ?>
