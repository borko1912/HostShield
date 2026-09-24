<?php
/** @var array $cfg @var array $admin */
$tab = (string)($_GET['tab'] ?? 'general');
$tabs = ['general' => __('General'), 'firewall' => __('Firewall'), 'backups' => __('Backups'), 'notifications' => __('Notifications'), 'security' => __('Security')];
if (!isset($tabs[$tab])) {
    $tab = 'general';
}
$open = static fn(string $section) => '<form method="post" class="form">' . csrf_field() . '<input type="hidden" name="action" value="settings_save"><input type="hidden" name="section" value="' . e($section) . '">';
?>
<div class="page-h"><h1><?= e(__('Settings')) ?></h1></div>
<nav class="tabs">
<?php foreach ($tabs as $t => $label): ?><a href="<?= e(url(['p' => 'settings', 'tab' => $t])) ?>" class="<?= $t === $tab ? 'on' : '' ?>"><?= e($label) ?></a><?php endforeach; ?>
</nav>

<?php if ($tab === 'general'):
    $m = (array)$cfg['monitor']; ?>
    <?= $open('general') ?>
    <section class="panel"><h2><?= e(__('Dashboard')) ?></h2>
        <div class="row2">
            <?= field_select('language', __('Language'), $cfg['language'], ['auto' => __('Automatic (browser)')] + SHIELD_LANGUAGES) ?>
            <?= field_select('timezone', __('Time zone'), $cfg['timezone'], array_combine(timezone_identifiers_list(), timezone_identifiers_list())) ?>
        </div>
        <?= field_text('dashboard_url', __('Dashboard address'), $cfg['dashboard_url'] ?: shield_dashboard_url(), e(__('Used in alerts and for the email relay from cron.'))) ?>
    </section>
    <section class="panel"><h2><?= e(__('Monitoring')) ?></h2>
        <div class="row3">
            <?= field_text('uptime_minutes', __('Uptime check, minutes'), $m['uptime_minutes'], '', ['type' => 'number', 'min' => 1, 'max' => 60]) ?>
            <?= field_text('integrity_minutes', __('File check, minutes'), $m['integrity_minutes'], '', ['type' => 'number', 'min' => 5, 'max' => 1440]) ?>
            <?= field_text('audit_hours', __('Security audit, hours'), $m['audit_hours'], '', ['type' => 'number', 'min' => 1, 'max' => 168]) ?>
        </div>
        <?= field_text('ssl_warn_days', __('Warn about SSL expiry, days before'), $m['ssl_warn_days'], '', ['type' => 'number', 'min' => 1, 'max' => 60]) ?>
        <?= field_check('auto_quarantine', __('Quarantine high-confidence malware automatically'), (bool)$m['auto_quarantine'],
            e(__('Web shells, PHP in upload folders and similar are moved out of the site the moment they are found. You get an alert and can put a file back.'))) ?>
        <?= field_check('update_check', __('Check GitHub for new HostShield versions'), (bool)$cfg['updates']['check']) ?>
    </section>
    <section class="panel"><h2><?= e(__('“Protected by” badge')) ?></h2>
        <p class="muted"><?= e(__('A small badge in the corner of protected sites, shown for a few seconds. Off by default.')) ?></p>
        <?= field_check('banner_enabled', __('Show the badge'), (bool)$cfg['banner']['enabled']) ?>
        <div class="row2">
            <?= field_text('banner_text', __('Text'), $cfg['banner']['text']) ?>
            <?= field_select('banner_show', __('When'), $cfg['banner']['show'], ['session' => __('Once per browser session'), 'once' => __('Once per year'), 'always' => __('On every page')]) ?>
        </div>
    </section>
    <button class="btn primary"><?= e(__('Save')) ?></button></form>

<?php elseif ($tab === 'firewall'):
    $w = (array)$cfg['waf']; ?>
    <?= $open('firewall') ?>
    <section class="panel"><h2><?= e(__('Mode')) ?></h2>
        <label class="check"><input type="radio" name="mode" value="log"<?= $w['mode'] !== 'block' ? ' checked' : '' ?>><span><b><?= e(__('Log only')) ?></b><small><?= e(__('Records attacks without stopping them. Start here for a few days to catch false positives.')) ?></small></span></label>
        <label class="check"><input type="radio" name="mode" value="block"<?= $w['mode'] === 'block' ? ' checked' : '' ?>><span><b><?= e(__('Block')) ?></b><small><?= e(__('Stops attacks and bans repeat offenders (1 h, then 2 h, 4 h … up to 7 days).')) ?></small></span></label>
    </section>
    <section class="panel"><h2><?= e(__('Protection')) ?></h2>
        <?= field_check('block_exec_in_uploads', __('Block PHP running from upload folders'), (bool)$w['block_exec_in_uploads'], e(__('Stops most web shells even when they were uploaded successfully.'))) ?>
        <?= field_check('wp_block_user_enum', __('WordPress: block user enumeration'), (bool)$w['wp_block_user_enum'], e(__('Hides usernames from /?author=1 and the REST users endpoint.'))) ?>
        <?= field_check('wp_block_xmlrpc', __('WordPress: block XML-RPC'), (bool)$w['wp_block_xmlrpc'], e(__('Stops brute force through xmlrpc.php. Jetpack and the WordPress mobile app need it.'))) ?>
    </section>
    <section class="panel"><h2><?= e(__('Limits and bans')) ?></h2>
        <div class="row3">
            <?= field_text('rate_limit_per_min', __('Requests per minute per IP'), $w['rate_limit_per_min'], e(__('0 = no limit')), ['type' => 'number', 'min' => 0]) ?>
            <?= field_text('login_limit', __('Login attempts'), $w['login_limit'], '', ['type' => 'number', 'min' => 1]) ?>
            <?= field_text('login_window', __('… within seconds'), $w['login_window'], '', ['type' => 'number', 'min' => 60]) ?>
        </div>
        <div class="row2">
            <?= field_text('strikes_to_ban', __('Blocked requests before a ban'), $w['strikes_to_ban'], '', ['type' => 'number', 'min' => 1]) ?>
            <?= field_text('ban_minutes', __('First ban, minutes'), $w['ban_minutes'], e(__('Doubles on every repeat, up to 7 days.')), ['type' => 'number', 'min' => 1]) ?>
        </div>
        <?= field_textarea('trusted_proxies', __('Trusted proxies (Cloudflare etc.)'), $w['trusted_proxies'], e(__('IP ranges of your CDN, one per line. Behind them, the visitor IP is read from CF-Connecting-IP / X-Forwarded-For.')), 3) ?>
    </section>
    <button class="btn primary"><?= e(__('Save')) ?></button></form>

<?php elseif ($tab === 'backups'):
    $b = (array)$cfg['backup'];
    $o = (array)$b['offsite']; ?>
    <?= $open('backups') ?>
    <section class="panel"><h2><?= e(__('Schedule and retention')) ?></h2>
        <?= field_check('enabled', __('Nightly backups'), (bool)$b['enabled']) ?>
        <div class="row3">
            <?= field_select('hour', __('Start at'), $b['hour'], array_combine(range(0, 23), array_map(static fn($h) => sprintf('%02d:00', $h), range(0, 23)))) ?>
            <?= field_text('max_file_mb', __('Skip files larger than, MB'), $b['max_file_mb'], '', ['type' => 'number', 'min' => 1]) ?>
        </div>
        <div class="row3">
            <?= field_text('keep_daily', __('Keep daily'), $b['keep_daily'], '', ['type' => 'number', 'min' => 1]) ?>
            <?= field_text('keep_weekly', __('Keep weekly'), $b['keep_weekly'], '', ['type' => 'number', 'min' => 0]) ?>
            <?= field_text('keep_monthly', __('Keep monthly'), $b['keep_monthly'], '', ['type' => 'number', 'min' => 0]) ?>
        </div>
        <p class="muted"><?= e(__('Example: 7 / 4 / 3 keeps the last week day by day, one backup per week for a month, and one per month for three months.')) ?></p>
    </section>
    <section class="panel"><h2><?= e(__('Default database user')) ?></h2>
        <p class="muted"><?= e(__('Used for sites without their own database credentials. Most sites get theirs from the app config automatically.')) ?></p>
        <div class="row3">
            <?= field_text('db_user', __('User'), $cfg['db']['user']) ?>
            <?= field_secret('db_pass', __('Password'), (string)$cfg['db']['pass']) ?>
            <?= field_text('db_host', __('Host'), $cfg['db']['host']) ?>
        </div>
        <input type="hidden" name="db_port" value="<?= (int)$cfg['db']['port'] ?>">
    </section>
    <section class="panel" data-switch="offsite_type"><h2><?= e(__('Off-site storage')) ?></h2>
        <p class="muted"><?= e(__('A copy outside this server survives a server failure, a hacked hosting account or a mistake. Recommended: Backblaze B2 or Cloudflare R2 (both have free tiers).')) ?></p>
        <?= field_select('offsite_type', __('Storage'), $o['type'], ['none' => __('None'), 's3' => __('S3-compatible (AWS, Backblaze B2, Cloudflare R2, Wasabi, MinIO)'), 'ftp' => __('FTP / FTPS')]) ?>
        <div data-when="s3">
            <?= field_text('s3_endpoint', __('Endpoint'), $o['s3']['endpoint'], e(__('e.g. https://s3.eu-central-003.backblazeb2.com, https://<account>.r2.cloudflarestorage.com, https://s3.eu-west-1.amazonaws.com'))) ?>
            <div class="row3">
                <?= field_text('s3_bucket', __('Bucket'), $o['s3']['bucket']) ?>
                <?= field_text('s3_region', __('Region'), $o['s3']['region'], e(__('auto for R2; e.g. eu-central-003 for B2'))) ?>
                <?= field_text('s3_prefix', __('Folder prefix'), $o['s3']['prefix']) ?>
            </div>
            <div class="row2">
                <?= field_text('s3_key', __('Access key ID'), $o['s3']['key'], '', ['autocomplete' => 'off']) ?>
                <?= field_secret('s3_secret', __('Secret access key'), (string)$o['s3']['secret']) ?>
            </div>
            <?= field_check('s3_path_style', __('Path-style URLs'), (bool)$o['s3']['path_style'], e(__('On for B2, R2, Wasabi and MinIO. Off for AWS buckets created after 2020.'))) ?>
        </div>
        <div data-when="ftp">
            <div class="row3">
                <?= field_text('ftp_host', __('Host'), $o['ftp']['host']) ?>
                <?= field_text('ftp_port', __('Port'), $o['ftp']['port'], '', ['type' => 'number']) ?>
                <?= field_text('ftp_dir', __('Folder'), $o['ftp']['dir']) ?>
            </div>
            <div class="row2">
                <?= field_text('ftp_user', __('User'), $o['ftp']['user'], '', ['autocomplete' => 'off']) ?>
                <?= field_secret('ftp_pass', __('Password'), (string)$o['ftp']['pass']) ?>
            </div>
            <?= field_check('ftp_ssl', __('Use FTPS (TLS)'), (bool)$o['ftp']['ssl']) ?>
        </div>
    </section>
    <div class="toolbar"><button class="btn primary"><?= e(__('Save')) ?></button>
        <button class="btn ghost" name="test" value="1"><?= e(__('Save and test connection')) ?></button></div></form>

<?php elseif ($tab === 'notifications'):
    $n = (array)$cfg['notify']; ?>
    <?= $open('notifications') ?>
    <section class="panel"><h2><?= e(__('Email')) ?></h2>
        <div class="row2">
            <?= field_text('email', __('Send alerts to'), $n['email'], e(__('Several addresses separated by commas.'))) ?>
            <?= field_text('mail_from', __('Sender address'), $n['mail_from'], e(__('Empty = shield@your-domain. Use an address of your own domain.'))) ?>
        </div>
        <div data-switch="transport">
        <?= field_select('transport', __('Send with'), $n['transport'], ['mail' => __('PHP mail() of the hosting'), 'smtp' => __('SMTP server (more reliable)')]) ?>
        <div data-when="smtp">
            <div class="row3">
                <?= field_text('smtp_host', __('SMTP host'), $n['smtp']['host']) ?>
                <?= field_text('smtp_port', __('Port'), $n['smtp']['port'], '', ['type' => 'number']) ?>
                <?= field_select('smtp_secure', __('Encryption'), $n['smtp']['secure'], ['tls' => 'STARTTLS (587)', 'ssl' => 'SSL/TLS (465)', 'none' => __('None')]) ?>
            </div>
            <div class="row2">
                <?= field_text('smtp_user', __('User'), $n['smtp']['user'], '', ['autocomplete' => 'off']) ?>
                <?= field_secret('smtp_pass', __('Password'), (string)$n['smtp']['pass']) ?>
            </div>
        </div>
        </div>
    </section>
    <section class="panel"><h2>Telegram</h2>
        <p class="muted"><?= __('Create a bot with <b>@BotFather</b>, send it any message, then open <code>https://api.telegram.org/bot&lt;token&gt;/getUpdates</code> to find your chat id.') ?></p>
        <div class="row2">
            <?= field_secret('tg_token', __('Bot token'), (string)$n['telegram']['token']) ?>
            <?= field_text('tg_chat', __('Chat id'), $n['telegram']['chat_id']) ?>
        </div>
        <?php if ($n['telegram']['token'] !== ''): ?><?= field_check('tg_clear', __('Remove Telegram'), false) ?><?php endif; ?>
    </section>
    <section class="panel"><h2><?= e(__('Chat webhook')) ?></h2>
        <div class="row2">
            <?= field_text('webhook_url', __('Webhook URL'), $n['webhook']['url'], e(__('Discord: channel settings → Integrations → Webhooks. Slack: Incoming Webhooks.'))) ?>
            <?= field_select('webhook_format', __('Format'), $n['webhook']['format'], ['discord' => 'Discord', 'slack' => 'Slack', 'generic' => __('Generic JSON')]) ?>
        </div>
    </section>
    <section class="panel"><h2><?= e(__('What to send')) ?></h2>
        <div class="checks-grid">
        <?php foreach (SHIELD_EVENTS as $ev => $label): ?><?= field_check('ev_' . $ev, __($label), !empty($n['events'][$ev])) ?><?php endforeach; ?>
        </div>
    </section>
    <div class="toolbar"><button class="btn primary"><?= e(__('Save')) ?></button></div></form>
    <div class="spaced"><?= post_button('notify_test', e(__('Send a test alert')), [], ['class' => 'ghost']) ?></div>

<?php elseif ($tab === 'security'):
    $new = (string)($_SESSION['totp_new'] ?? '');
    $codes = (array)($_SESSION['recovery_show'] ?? []);
    unset($_SESSION['recovery_show']); ?>
    <div class="grid2">
        <section class="panel">
            <h2><?= e(__('Two-factor login (2FA)')) ?></h2>
            <?php if ($codes): ?>
                <div class="alert warn"><b><?= e(__('Recovery codes — shown only once.')) ?></b> <?= e(__('Each works once if you lose your phone. Store them in a password manager.')) ?>
                    <pre class="codes" id="codes"><?= e(implode("\n", $codes)) ?></pre><button type="button" class="btn xs ghost" data-copy="codes"><?= e(__('Copy')) ?></button></div>
            <?php endif; ?>
            <?php if (!empty($admin['totp'])): ?>
                <p class="ok"><?= e(__('On ✓')) ?> · <?= e(__('%d recovery codes left', count((array)($admin['recovery'] ?? [])))) ?></p>
                <form method="post" class="form"><?= csrf_field() ?>
                    <label class="field"><span><?= e(__('Password')) ?></span><input type="password" name="password" required autocomplete="current-password"></label>
                    <div class="toolbar"><button class="btn ghost" name="action" value="recovery_new"><?= e(__('New recovery codes')) ?></button>
                    <button class="btn danger" name="action" value="totp_disable" data-confirm="<?= e(__('Turn off two-factor login?')) ?>"><?= e(__('Turn off 2FA')) ?></button></div></form>
            <?php elseif ($new): ?>
                <p><?= e(__('Scan with Google Authenticator, Microsoft Authenticator, Authy or 1Password:')) ?></p>
                <div class="qr" data-qr="<?= e('otpauth://totp/HostShield:' . rawurlencode((string)$admin['user']) . '?secret=' . $new . '&issuer=HostShield') ?>"></div>
                <p class="muted"><?= e(__('or enter the key by hand:')) ?> <code><?= e(trim(chunk_split($new, 4, ' '))) ?></code></p>
                <form method="post" class="form"><?= csrf_field() ?><input type="hidden" name="action" value="totp_enable">
                    <label class="field"><span><?= e(__('6-digit code from the app')) ?></span><input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
                    <button class="btn primary"><?= e(__('Turn on')) ?></button></form>
            <?php else: ?>
                <p class="warn"><?= e(__('Off. The dashboard can restore and delete everything — turn it on.')) ?></p>
                <?= post_button('totp_start', e(__('Turn on 2FA')), [], ['class' => 'primary']) ?>
            <?php endif; ?>
        </section>
        <section class="panel">
            <h2><?= e(__('Change password')) ?></h2>
            <form method="post" class="form"><?= csrf_field() ?><input type="hidden" name="action" value="password">
                <label class="field"><span><?= e(__('Current password')) ?></span><input type="password" name="old" required autocomplete="current-password"></label>
                <label class="field"><span><?= e(__('New password (min. 12 characters)')) ?></span><input type="password" name="new" minlength="12" required autocomplete="new-password"></label>
                <label class="field"><span><?= e(__('Repeat the new password')) ?></span><input type="password" name="new2" minlength="12" required autocomplete="new-password"></label>
                <button class="btn"><?= e(__('Change')) ?></button></form>
        </section>
    </div>
    <?= $open('security') ?>
    <section class="panel"><h2><?= e(__('Dashboard access')) ?></h2>
        <?= field_textarea('admin_allowed_ips', __('Allow the dashboard only from these IPs'), $cfg['admin_allowed_ips'], e(__('One IP or range per line. Empty = from anywhere (password + 2FA). Your IP now: %s', shield_client_ip())), 3) ?>
        <?= field_text('session_minutes', __('Log out after inactivity, minutes'), $cfg['session_minutes'], '', ['type' => 'number', 'min' => 5, 'max' => 1440]) ?>
        <p class="muted"><?= e(__('Last login: %s', !empty($admin['last_login']) ? date('d.m.Y H:i', (int)$admin['last_login']) . ' · ' . $admin['last_ip'] : '—')) ?></p>
    </section>
    <button class="btn primary"><?= e(__('Save')) ?></button></form>
<?php endif; ?>
