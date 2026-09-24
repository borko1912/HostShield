<?php
/** @var array $cfg @var array $state @var string $title */

$k = site_key_param();
$s = shield_site($k);
$title = $s['title'];
$tab = (string)($_GET['tab'] ?? 'overview');
$tabs = ['overview' => __('Overview'), 'backups' => __('Backups'), 'files' => __('Files'), 'firewall' => __('Firewall'), 'audit' => __('Audit'), 'settings' => __('Settings')];
if (!isset($tabs[$tab])) {
    $tab = 'overview';
}
$rep = shield_integrity_report($k);
$audit = shield_audit_result($k);
$wafState = shield_site_waf_state($s);
$hbf = shield_path('waf/heartbeat/' . $k);
$hbAge = is_file($hbf) ? time() - (int)filemtime($hbf) : null;
$mode = (string)(($s['waf_mode'] ?? null) ?: ($cfg['waf']['mode'] ?? 'log'));
$suspicious = count((array)($rep['malware'] ?? [])) + count((array)($rep['wp']['modified'] ?? [])) + count((array)($rep['wp']['unknown'] ?? []));
$changes = count((array)($rep['added'] ?? [])) + count((array)($rep['modified'] ?? [])) + count((array)($rep['removed'] ?? []));
$hidden = static fn(array $f = []) => csrf_field() . '<input type="hidden" name="site" value="' . e($k) . '">';
?>
<div class="page-h">
    <div>
        <h1><?= e($s['title']) ?> <?= grade_badge($audit) ?></h1>
        <p class="muted"><?= $s['url'] !== '' ? '<a href="' . e($s['url']) . '" target="_blank" rel="noopener">' . e($s['url']) . '</a> · ' : '' ?><?= e(platform_label((string)$s['platform'])) ?> · <code><?= e($s['path']) ?></code></p>
    </div>
    <div class="toolbar">
        <?= post_button('integrity_now', e(__('Scan files')), ['site' => $k], ['class' => 'ghost']) ?>
        <?= post_button('backup_now', e(__('Back up now')), ['site' => $k], ['class' => 'primary']) ?>
    </div>
</div>

<nav class="tabs" aria-label="<?= e(__('Site sections')) ?>">
<?php foreach ($tabs as $t => $label): ?>
    <a href="<?= e(url(['p' => 'site', 'site' => $k, 'tab' => $t])) ?>" class="<?= $t === $tab ? 'on' : '' ?>"><?= e($label) ?>
        <?php if ($t === 'files' && $suspicious): ?><span class="count bad"><?= $suspicious ?></span><?php elseif ($t === 'files' && $changes): ?><span class="count warn"><?= $changes ?></span><?php endif; ?></a>
<?php endforeach; ?>
</nav>

<?php if ($tab === 'overview'):
    $up = shield_json_read(shield_path('uptime/' . $k . '.json'));
    $list = shield_list_backups($k);
    ?>
    <?php if ($suspicious): ?>
        <div class="alert err"><b><?= e(__('%d suspicious files found.', $suspicious)) ?></b> <a href="<?= e(url(['p' => 'site', 'site' => $k, 'tab' => 'files'])) ?>"><?= e(__('Review them')) ?></a></div>
    <?php endif; ?>
    <div class="grid2">
        <section class="panel">
            <h2><?= e(__('Firewall')) ?></h2>
            <p><?= e(__('Status')) ?>: <b class="<?= $wafState === 'on' ? 'ok' : 'bad' ?>"><?= e(['on' => __('enabled'), 'off' => __('disabled'), 'other' => __('another auto_prepend_file is set')][$wafState]) ?></b>
                · <?= e(__('mode')) ?>: <b><?= e(['log' => __('log only'), 'block' => __('block'), 'off' => __('off')][$mode] ?? $mode) ?></b>
                · <?= e(__('last request seen')) ?>: <b><?= $hbAge === null ? e(__('never')) : e(shield_ago(time() - $hbAge)) ?></b></p>
            <?php if ($wafState !== 'other'): ?>
                <?= $wafState === 'on'
                    ? post_button('waf_off', e(__('Disable firewall')), ['site' => $k], ['class' => 'ghost', 'confirm' => __('Disable the firewall for this site?')])
                    : post_button('waf_on', e(__('Enable firewall')), ['site' => $k], ['class' => 'primary']) ?>
            <?php endif; ?>
            <p class="muted"><?= e(__('Setting file: %s', shield_site_ini_path(['path' => shield_site_docroot($s)]))) ?>.
                <?= e(__('If a deploy overwrites this file, enable the firewall again or add the line to your repository:')) ?></p>
            <div class="copy"><code id="prepend"><?= e(shield_waf_prepend_line()) ?></code><button type="button" class="btn xs ghost" data-copy="prepend"><?= e(__('Copy')) ?></button></div>
        </section>
        <section class="panel">
            <h2><?= e(__('Health')) ?></h2>
            <ul class="kv">
                <li><span><?= e(__('Uptime 24 h')) ?></span><b><?= ($pct = shield_uptime_percent($up)) !== null ? e($pct . '%') : '—' ?></b></li>
                <li><span><?= e(__('Response')) ?></span><b class="<?= ($up['fails'] ?? 0) ? 'bad' : 'ok' ?>"><?= empty($up['checked']) ? '—' : e((int)$up['code'] . ' · ' . (int)$up['ms'] . ' ms') ?></b></li>
                <li><span><?= e(__('SSL certificate')) ?></span><b class="<?= isset($up['ssl']['days']) && $up['ssl']['days'] !== null && $up['ssl']['days'] < 14 ? 'bad' : '' ?>"><?= isset($up['ssl']['days']) && $up['ssl']['days'] !== null ? e(__('%d days left', (int)$up['ssl']['days'])) : '—' ?></b></li>
                <li><span><?= e(__('Last backup')) ?></span><b><?= $list ? e(shield_ago((int)$list[0]['created'])) : e(__('none')) ?></b></li>
                <li><span><?= e(__('Files checked')) ?></span><b><?= !empty($rep['checked']) ? e(shield_ago((int)$rep['checked'])) : '—' ?></b></li>
                <li><span><?= e(__('Security grade')) ?></span><b><?= $audit ? e($audit['grade'] . ' · ' . $audit['score'] . '/100') : '—' ?></b></li>
            </ul>
            <?= uptime_strip($up) ?>
        </section>
    </div>
    <h2><?= e(__('Latest attacks on this site')) ?></h2>
    <?php render_events(shield_waf_events(30, null, $k, 7)); ?>

<?php elseif ($tab === 'backups'):
    $list = shield_list_backups($k);
    $remote = [];
    $remoteErr = '';
    if (shield_offsite_enabled() && isset($_GET['remote'])) {
        try {
            $remote = array_diff_key(shield_offsite_list($k), array_flip(array_column($list, 'name')));
        } catch (Throwable $e) {
            $remoteErr = $e->getMessage();
        }
    }
    $b = (array)$cfg['backup'];
    ?>
    <p class="muted"><?= e(__('Kept: last %d daily, %d weekly and %d monthly backups. Nightly at %02d:00.', (int)$b['keep_daily'], (int)$b['keep_weekly'], (int)$b['keep_monthly'], (int)$b['hour'])) ?>
        <?= shield_offsite_enabled() ? e(__('Copied off-site (%s).', strtoupper(shield_offsite_type()))) : '<a href="' . e(url(['p' => 'settings', 'tab' => 'backups'])) . '">' . e(__('Add off-site storage')) . '</a>' ?></p>
    <?php if (empty($s['backup'])): ?><div class="alert warn"><?= e(__('Nightly backups are switched off for this site (Settings tab).')) ?></div><?php endif; ?>
    <div class="scroll"><table>
        <thead><tr><th><?= e(__('Date')) ?></th><th><?= e(__('Type')) ?></th><th><?= e(__('Size')) ?></th><th><?= e(__('Contents')) ?></th><th></th></tr></thead><tbody>
        <?php foreach ($list as $m): ?>
        <tr>
            <td><b><?= e(date('d.m.Y H:i', (int)$m['created'])) ?></b><div class="muted"><?= e(shield_ago((int)$m['created'])) ?></div></td>
            <td><span class="tag <?= e($m['kind']) ?>"><?= e(['daily' => __('daily'), 'manual' => __('manual'), 'pre-restore' => __('safety')][$m['kind']] ?? $m['kind']) ?></span></td>
            <td><?= e(shield_human_size((float)$m['total_size'])) ?></td>
            <td class="muted"><?= e(__('%d files', (int)$m['files']['count'])) ?><?php foreach ((array)$m['databases'] as $d): ?> · <?= e($d['name']) ?> (<?= e(__('%d tables', (int)$d['tables'])) ?>)<?php endforeach; ?>
                <div><a href="<?= e(url(['p' => 'download', 'site' => $k, 'backup' => $m['name'], 'file' => $m['files']['file']])) ?>">files.zip</a>
                <?php foreach ((array)$m['databases'] as $d): ?> · <a href="<?= e(url(['p' => 'download', 'site' => $k, 'backup' => $m['name'], 'file' => $d['file']])) ?>"><?= e($d['file']) ?></a><?php endforeach; ?></div>
            </td>
            <td class="actions">
                <details class="pop">
                    <summary class="btn sm"><?= e(__('Restore')) ?></summary>
                    <form method="post" class="pop-body">
                        <?= $hidden() ?><input type="hidden" name="action" value="restore"><input type="hidden" name="backup" value="<?= e($m['name']) ?>">
                        <label class="check"><input type="radio" name="scope" value="all" checked><span><?= e(__('Everything (files + database)')) ?></span></label>
                        <label class="check"><input type="radio" name="scope" value="files"><span><?= e(__('Files only')) ?></span></label>
                        <label class="check"><input type="radio" name="scope" value="db"><span><?= e(__('Database only')) ?></span></label>
                        <p class="muted"><?= e(__('The current state is saved as a safety backup first. Files that are not in the archive are removed.')) ?></p>
                        <label class="field"><span><?= e(__('Type %s to confirm', $k)) ?></span><input name="confirm" autocomplete="off" required></label>
                        <button class="btn danger"><?= e(__('Restore from %s', date('d.m H:i', (int)$m['created']))) ?></button>
                    </form>
                </details>
                <?php if (count($list) > 1): ?>
                    <?= post_button('delete_backup', e(__('Delete')), ['site' => $k, 'backup' => $m['name']], ['class' => 'sm ghost', 'confirm' => __('Delete backup %s?', $m['name'])]) ?>
                <?php endif; ?>
            </td>
        </tr>
        <?php endforeach; ?>
        <?php if (!$list): ?><tr><td colspan="5" class="muted"><?= e(__('No backups yet. Click “Back up now”.')) ?></td></tr><?php endif; ?>
    </tbody></table></div>
    <?php if (shield_offsite_enabled()): ?>
        <h2><?= e(__('Off-site backups')) ?></h2>
        <?php if (!isset($_GET['remote'])): ?>
            <p><a class="btn ghost" href="<?= e(url(['p' => 'site', 'site' => $k, 'tab' => 'backups', 'remote' => 1])) ?>"><?= e(__('Show backups stored off-site')) ?></a></p>
        <?php elseif ($remoteErr !== ''): ?>
            <div class="alert err"><?= e($remoteErr) ?></div>
        <?php else: ?>
            <p class="muted"><?= e(__('Backups that exist only in the off-site storage. Download one to restore from it.')) ?></p>
            <table><tbody>
            <?php foreach (array_keys($remote) as $name): ?>
                <tr><td><?= e($name) ?></td><td class="actions"><?= post_button('offsite_fetch', e(__('Download to this server')), ['site' => $k, 'backup' => $name], ['class' => 'sm']) ?></td></tr>
            <?php endforeach; ?>
            <?php if (!$remote): ?><tr><td class="muted"><?= e(__('Every off-site backup is also here.')) ?></td></tr><?php endif; ?>
            </tbody></table>
        <?php endif; ?>
    <?php endif; ?>

<?php elseif ($tab === 'files'):
    $wp = (array)($rep['wp'] ?? []);
    $quarantine = shield_quarantine_list($k);
    ?>
    <p class="muted"><?= !empty($rep['checked'])
        ? e(__('Checked %s · %d code files and %d uploads watched.', shield_ago((int)$rep['checked']), (int)($rep['files_watched'] ?? 0), (int)($rep['uploads_watched'] ?? 0)))
        : e(__('Not checked yet. The first check runs within an hour, or click “Scan files”.')) ?></p>

    <?php if (!empty($rep['malware'])): ?>
        <div class="alert err"><b><?= e(__('Suspicious code (%d)', count($rep['malware']))) ?></b> — <?= e(__('Review each file. Quarantine moves it out of the site (you can put it back).')) ?></div>
        <div class="scroll"><table><thead><tr><th><?= e(__('File')) ?></th><th><?= e(__('Why')) ?></th><th></th></tr></thead><tbody>
        <?php foreach ($rep['malware'] as $f => $x): ?>
            <tr><td><code><?= e($f) ?></code><div class="muted"><?= e(date('d.m H:i', (int)$x['t'])) ?></div></td>
                <td><?php foreach ((array)$x['rules'] as $r): ?><span class="rule <?= ($x['level'] ?? '') === 'high' ? 'bad' : 'warn' ?>"><?= e($r) ?></span> <?php endforeach; ?></td>
                <td class="actions">
                    <?= post_button('quarantine', e(__('Quarantine')), ['site' => $k, 'file' => $f], ['class' => 'sm danger', 'confirm' => __('Move %s to quarantine?', $f)]) ?>
                    <?= post_button('scan_ignore', e(__('It is safe')), ['site' => $k, 'file' => $f], ['class' => 'sm ghost', 'confirm' => __('Mark %s as safe? It will be flagged again if it changes.', $f)]) ?>
                </td></tr>
        <?php endforeach; ?>
        </tbody></table></div>
    <?php endif; ?>

    <?php if (($s['platform'] ?? '') === 'wordpress'): ?>
        <h2>WordPress <?= !empty($wp['version']) ? e($wp['version']) : '' ?>
            <?php if (!empty($wp['latest']) && !empty($wp['version']) && version_compare($wp['version'], $wp['latest'], '<')): ?><span class="badge warn"><?= e(__('update to %s', $wp['latest'])) ?></span><?php endif; ?></h2>
        <?php if (!$wp): ?>
            <p class="muted"><?= e(__('Core and plugin verification runs with the next scan.')) ?></p>
        <?php elseif (!empty($wp['error'])): ?>
            <div class="alert warn"><?= e($wp['error']) ?></div>
        <?php else:
            $coreBad = array_merge((array)$wp['modified'], (array)$wp['unknown']); ?>
            <p class="<?= $coreBad ? 'bad' : 'ok' ?>"><?= $coreBad ? e(__('%d core files differ from wordpress.org:', count($coreBad))) : e(__('All core files match wordpress.org (checked %s).', shield_ago((int)$wp['checked']))) ?></p>
            <?php if ($coreBad): ?>
                <table><tbody>
                <?php foreach ((array)$wp['modified'] as $f): ?><tr><td><code><?= e($f) ?></code></td><td class="bad"><?= e(__('modified')) ?></td><td class="actions"></td></tr><?php endforeach; ?>
                <?php foreach ((array)$wp['unknown'] as $f): ?><tr><td><code><?= e($f) ?></code></td><td class="bad"><?= e(__('not part of WordPress')) ?></td>
                    <td class="actions"><?= post_button('quarantine', e(__('Quarantine')), ['site' => $k, 'file' => $f], ['class' => 'sm danger', 'confirm' => __('Move %s to quarantine?', $f)]) ?></td></tr><?php endforeach; ?>
                </tbody></table>
                <p class="muted"><?= e(__('Modified core files: reinstall WordPress from Dashboard → Updates → “Re-install version”.')) ?></p>
            <?php endif; ?>
            <?php if (!empty($wp['plugins'])): ?>
                <table><thead><tr><th><?= e(__('Plugin')) ?></th><th><?= e(__('Version')) ?></th><th><?= e(__('Integrity')) ?></th></tr></thead><tbody>
                <?php foreach ($wp['plugins'] as $slug => $pl): ?>
                    <tr><td><?= e($pl['name']) ?> <span class="muted"><?= e($slug) ?></span></td><td><?= e($pl['version']) ?></td>
                        <td class="<?= $pl['status'] === 'changed' ? 'bad' : ($pl['status'] === 'ok' ? 'ok' : 'muted') ?>"><?= e(['ok' => __('matches wordpress.org'), 'changed' => __('changed'), 'unverified' => __('not on wordpress.org (not verifiable)')][$pl['status']] ?? $pl['status']) ?>
                        <?php foreach (array_slice(array_merge((array)$pl['modified'], (array)$pl['unknown']), 0, 8) as $f): ?><div><code><?= e($f) ?></code></div><?php endforeach; ?></td></tr>
                <?php endforeach; ?>
                </tbody></table>
            <?php endif; ?>
        <?php endif; ?>
    <?php endif; ?>

    <h2><?= e(__('Changes since the last approval')) ?></h2>
    <?php
    $groups = ['added' => __('New files'), 'modified' => __('Modified'), 'removed' => __('Deleted')];
    $any = false;
    foreach ($groups as $g => $label):
        if (empty($rep[$g])) {
            continue;
        }
        $any = true; ?>
        <h3><?= e($label) ?> (<?= count($rep[$g]) ?>)</h3>
        <table><tbody><?php foreach (array_slice((array)$rep[$g], 0, 300, true) as $f => $t): ?><tr><td><code><?= e($f) ?></code></td><td class="muted nowrap"><?= e(date('d.m H:i', (int)$t)) ?></td></tr><?php endforeach; ?></tbody></table>
    <?php endforeach; ?>
    <?php if ($any): ?>
        <p class="muted"><?= e(__('If these are from your own deploy or update, approve them. If you did not make them, the site may be hacked: restore it from a backup.')) ?></p>
        <?= post_button('integrity_accept', e(__('Approve changes (they are mine)')), ['site' => $k], ['class' => 'primary']) ?>
    <?php elseif (!empty($rep['checked'])): ?>
        <p class="ok"><?= e(__('No changes since the approved state.')) ?></p>
    <?php endif; ?>

    <?php if ($quarantine): ?>
        <h2><?= e(__('Quarantine')) ?></h2>
        <table><thead><tr><th><?= e(__('File')) ?></th><th><?= e(__('When')) ?></th><th></th></tr></thead><tbody>
        <?php foreach ($quarantine as $q): ?>
            <tr><td><code><?= e($q['rel']) ?></code><div class="muted"><?= e(implode(', ', (array)$q['rules'])) ?></div></td><td class="nowrap"><?= e(date('d.m.Y H:i', (int)$q['t'])) ?></td>
                <td class="actions"><?= post_button('quarantine_restore', e(__('Put back')), ['site' => $k, 'id' => $q['id']], ['class' => 'sm ghost', 'confirm' => __('Put %s back into the site?', $q['rel'])]) ?>
                    <?= post_button('quarantine_delete', e(__('Delete forever')), ['site' => $k, 'id' => $q['id']], ['class' => 'sm danger', 'confirm' => __('Delete %s permanently?', $q['rel'])]) ?></td></tr>
        <?php endforeach; ?>
        </tbody></table>
        <p class="muted"><?= e(__('Quarantined files are deleted automatically after 90 days.')) ?></p>
    <?php endif; ?>

<?php elseif ($tab === 'firewall'):
    $cat = shield_waf_rule_catalog();
    ?>
    <p><?= e(__('Mode for this site')) ?>: <b><?= e(['log' => __('log only'), 'block' => __('block'), 'off' => __('off')][$mode] ?? $mode) ?></b>
        <?= $s['waf_mode'] === null ? '<span class="muted">(' . e(__('global setting')) . ')</span>' : '' ?> ·
        <?= e(__('Lockdown')) ?>: <b class="<?= $s['lockdown'] ? 'ok' : 'muted' ?>"><?= e($s['lockdown'] ? __('on') : __('off')) ?></b>
        · <a href="<?= e(url(['p' => 'site', 'site' => $k, 'tab' => 'settings'])) ?>#firewall"><?= e(__('change')) ?></a></p>

    <h2><?= e(__('Exceptions (false positives)')) ?></h2>
    <p class="muted"><?= e(__('Rules that are not checked on a path of this site. Add one with “Not an attack” next to an event.')) ?></p>
    <table><thead><tr><th><?= e(__('Rule')) ?></th><th><?= e(__('Path starts with')) ?></th><th></th></tr></thead><tbody>
    <?php foreach ((array)$s['waf_exceptions'] as $i => $ex): ?>
        <tr><td><span class="rule"><?= e($ex['rule']) ?></span> <span class="muted"><?= e(isset($cat[$ex['rule']]) ? __($cat[$ex['rule']][1]) : __('all rules')) ?></span></td>
            <td><code><?= e($ex['path'] ?: '/') ?></code></td>
            <td class="actions"><?= post_button('waf_exception_remove', e(__('Remove')), ['site' => $k, 'index' => $i], ['class' => 'sm ghost']) ?></td></tr>
    <?php endforeach; ?>
    <?php if (!$s['waf_exceptions']): ?><tr><td colspan="3" class="muted"><?= e(__('None.')) ?></td></tr><?php endif; ?>
    </tbody></table>

    <h2><?= e(__('Events, last 7 days')) ?></h2>
    <?php render_events(shield_waf_events(300, null, $k, 7)); ?>

<?php elseif ($tab === 'audit'): ?>
    <div class="page-h">
        <p class="muted"><?= $audit ? e(__('Checked %s.', shield_ago((int)$audit['checked']))) : e(__('No audit yet.')) ?></p>
        <?= post_button('audit_now', e(__('Run audit now')), ['site' => $k], ['class' => 'ghost']) ?>
    </div>
    <?php if ($audit): ?>
        <div class="audit-head"><?= grade_badge($audit, 'xl') ?><div><b><?= (int)$audit['score'] ?>/100</b>
            <p class="muted"><?= e(__('%d of %d checks passed.', count(array_filter($audit['checks'], static fn($c) => $c['status'] === 'pass')), count($audit['checks']))) ?></p></div></div>
        <?php
        $order = ['fail' => 0, 'warn' => 1, 'pass' => 2];
        $sevOrder = array_flip(array_keys(SHIELD_SEVERITY_POINTS));
        $checks = $audit['checks'];
        usort($checks, static fn($a, $b) => [$order[$a['status']], $sevOrder[$a['severity']]] <=> [$order[$b['status']], $sevOrder[$b['severity']]]);
        ?>
        <ul class="checks">
        <?php foreach ($checks as $c): ?>
            <li class="<?= e($c['status']) ?>">
                <span class="st" aria-label="<?= e($c['status']) ?>"><?= $c['status'] === 'pass' ? '✓' : ($c['status'] === 'warn' ? '!' : '✗') ?></span>
                <div><b><?= e($c['title']) ?></b> <?= $c['status'] !== 'pass' ? severity_badge($c['severity']) : '' ?>
                    <?php if ($c['detail'] !== ''): ?><div class="muted"><?= e($c['detail']) ?></div><?php endif; ?>
                    <?php if ($c['fix'] !== ''): ?><div class="fix">→ <?= e($c['fix']) ?></div><?php endif; ?></div>
            </li>
        <?php endforeach; ?>
        </ul>
    <?php endif; ?>

<?php elseif ($tab === 'settings'):
    $f = static fn(string $n) => 'site[' . $n . ']';
    ?>
    <form method="post" class="form">
        <?= $hidden() ?><input type="hidden" name="action" value="site_save">
        <section class="panel"><h2><?= e(__('General')) ?></h2>
            <div class="row2">
                <?= field_text($f('title'), __('Name'), $s['title']) ?>
                <?= field_select($f('platform'), __('Platform'), $s['platform'], SHIELD_PLATFORMS) ?>
            </div>
            <?= field_text($f('url'), __('Public URL'), $s['url'], e(__('Used for uptime, SSL and the audit.'))) ?>
            <?= field_textarea($f('hosts'), __('Host names'), $s['hosts'], e(__('One per line. The firewall uses them to recognize the site.')), 2) ?>
            <?= field_text($f('path'), __('Folder'), $s['path']) ?>
        </section>
        <section class="panel"><h2><?= e(__('Backups')) ?></h2>
            <?= field_check($f('backup'), __('Include in the nightly backup'), (bool)$s['backup']) ?>
            <?= field_textarea($f('databases'), __('Databases'), $s['databases'], e(__('One per line.')), 2) ?>
            <?= field_textarea($f('db_patterns'), __('Database patterns'), $s['db_patterns'], e(__('SQL LIKE patterns for databases created on the fly, e.g. myapp\_%')), 2) ?>
            <div class="row3">
                <?= field_text($f('db][user'), __('Database user'), $s['db']['user'] ?? '', e(__('Empty = the global user from Settings → Backups.'))) ?>
                <?= field_secret($f('db][pass'), __('Database password'), (string)($s['db']['pass'] ?? '')) ?>
                <?= field_text($f('db][host'), __('Database host'), $s['db']['host'] ?? 'localhost') ?>
            </div>
            <input type="hidden" name="site[db][port]" value="<?= (int)($s['db']['port'] ?? 3306) ?>">
            <?= field_textarea($f('exclude'), __('Excluded paths'), $s['exclude'], e(__('Glob patterns relative to the site folder, one per line (caches, logs).')), 4) ?>
        </section>
        <section class="panel" id="firewall"><h2><?= e(__('Firewall')) ?></h2>
            <?= field_select($f('waf_mode'), __('Mode'), $s['waf_mode'] ?? '', ['' => __('Global setting (%s)', $cfg['waf']['mode']), 'log' => __('Log only'), 'block' => __('Block'), 'off' => __('Off (maintenance only)')]) ?>
            <?= field_textarea($f('upload_dirs'), __('Upload folders'), $s['upload_dirs'], e(__('PHP never runs from these folders, and every file in them is scanned.')), 2) ?>
            <?= field_check($f('lockdown'), __('Lockdown: only approved scripts may run'), (bool)$s['lockdown'],
                e(__('The strongest protection against web shells: a new PHP file cannot run until you approve it on the Files tab. After updates or deploys, approve the changes.'))) ?>
            <?= field_textarea($f('waf_skip_paths'), __('Paths without content inspection'), $s['waf_skip_paths'], e(__('Path prefixes, e.g. /admin/editor. Prefer exceptions for single rules.')), 2) ?>
            <?= field_textarea($f('waf_disabled_rules'), __('Rules switched off for this site'), $s['waf_disabled_rules'], e(__('Rule ids, one per line.')), 2) ?>
            <?= field_check($f('banner'), __('Show the “Protected by” badge (when enabled globally)'), (bool)$s['banner']) ?>
        </section>
        <button class="btn primary"><?= e(__('Save')) ?></button>
    </form>
    <div class="toolbar spaced">
        <?= post_button('site_detect_db', e(__('Detect database from app config')), ['site' => $k], ['class' => 'ghost']) ?>
        <?= post_button('site_test_db', e(__('Test database connection')), ['site' => $k], ['class' => 'ghost']) ?>
    </div>
    <section class="panel danger-zone">
        <h2><?= e(__('Remove site')) ?></h2>
        <p class="muted"><?= e(__('Stops protecting and backing up this site. The firewall line is removed; existing backups stay in the data folder.')) ?></p>
        <form method="post" class="row"><?= $hidden() ?><input type="hidden" name="action" value="site_remove">
            <input name="confirm" placeholder="<?= e(__('Type %s to confirm', $k)) ?>" autocomplete="off" required>
            <button class="btn danger"><?= e(__('Remove')) ?></button></form>
    </section>
<?php endif; ?>
