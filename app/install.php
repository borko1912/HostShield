<?php
declare(strict_types=1);

// First-run installer (also used to create a new admin account if admin.json was deleted).
// Unlock rule: the files were uploaded less than 24 hours ago, or a file named
// "install.unlock" exists next to index.php. This stops strangers from claiming a fresh install.

$root = str_replace('\\', '/', shield_root());
$installed = shield_installed();
$unlockFile = $root . '/install.unlock';
$fresh = time() - (int)@filemtime($root . '/index.php') < 86400;
$unlocked = is_file($unlockFile) || (!$installed && $fresh);

$checks = [
    [PHP_VERSION_ID >= 80100, 'PHP 8.1+', PHP_VERSION, true],
    [class_exists('ZipArchive'), 'zip', __('needed for file backups'), true],
    [class_exists('mysqli'), 'mysqli', __('needed for database backups'), true],
    [function_exists('curl_init'), 'curl', __('needed for uptime checks, alerts and off-site storage'), true],
    [function_exists('openssl_x509_parse'), 'openssl', __('needed for SSL checks'), false],
    [function_exists('mb_substr'), 'mbstring', '', true],
    [function_exists('ftp_connect'), 'ftp', __('only for FTP off-site storage'), false],
    [is_writable($root), __('Writable install folder'), $root, false],
];
$blocking = array_filter($checks, static fn($c) => !$c[0] && $c[3]);

$suggestData = dirname($root) . '/hostshield-data';
$docRoot = rtrim(str_replace('\\', '/', (string)($_SERVER['DOCUMENT_ROOT'] ?? '')), '/');
$err = '';
$configCode = '';

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && $unlocked && !$blocking) {
    shield_csrf_check();
    $user = trim((string)($_POST['user'] ?? ''));
    $pass = (string)($_POST['password'] ?? '');
    $email = trim((string)($_POST['email'] ?? ''));
    $dataDir = $installed ? shield_path() : rtrim(str_replace('\\', '/', trim((string)($_POST['data_dir'] ?? ''))), '/');
    if (!preg_match('/^[A-Za-z0-9_.@-]{3,60}$/', $user)) {
        $err = __('Username: 3–60 letters, digits or . _ - @');
    } elseif (strlen($pass) < 12) {
        $err = __('The password must be at least 12 characters.');
    } elseif ($pass !== (string)($_POST['password2'] ?? '')) {
        $err = __('The passwords do not match.');
    } elseif ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $err = __('Invalid email address.');
    } elseif (!$installed && ($dataDir === '' || str_starts_with($dataDir . '/', $root . '/'))) {
        $err = __('The data folder must be outside the HostShield folder.');
    } elseif (!$installed && !is_dir($dataDir) && !@mkdir($dataDir, 0700, true)) {
        $err = __('Cannot create %s. Create it in the File Manager and try again.', $dataDir);
    } elseif (!$installed && !is_writable($dataDir)) {
        $err = __('%s is not writable.', $dataDir);
    } else {
        if (!$installed) {
            $tz = (string)($_POST['timezone'] ?? '');
            $settings = shield_defaults();
            $settings['timezone'] = in_array($tz, timezone_identifiers_list(), true) ? $tz : $settings['timezone'];
            $settings['language'] = isset(SHIELD_LANGUAGES[$_POST['language'] ?? '']) ? (string)$_POST['language'] : 'auto';
            $settings['notify']['email'] = $email;
            $https = shield_https();
            $settings['dashboard_url'] = ($https ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? 'localhost') . rtrim(dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/')), '/\\');
            $found = [];
            foreach (shield_discover_sites() as $d) {
                $found[$d['path']] = $d;
            }
            foreach ((array)($_POST['paths'] ?? []) as $path) {
                if (isset($found[$path])) {
                    $site = shield_site_from_discovery($found[$path]);
                    $settings['sites'][shield_site_key($site['title'], $settings['sites'])] = $site;
                }
            }
            shield_php_write($dataDir . '/settings.php', shield_normalize($settings), 'HostShield settings. Managed from the dashboard.');
            $configCode = "<?php\n// HostShield: location of the data folder. Everything else is in <data_dir>/settings.php.\nreturn ['data_dir' => " . var_export($dataDir, true) . "];\n";
            if (@file_put_contents($root . '/config.php', $configCode, LOCK_EX) === false) {
                $err = __('Cannot write config.php. Create it by hand with the content below, then reload this page.');
            }
        }
        if ($err === '') {
            shield_config(true);
            shield_protect_data_dir();
            shield_relay_token();
            $admin = ['user' => $user, 'hash' => password_hash($pass, PASSWORD_DEFAULT), 'totp' => '', 'created' => time()];
            shield_admin_save($admin);
            @unlink($unlockFile);
            shield_log('setup', ($installed ? 'Admin account re-created' : 'Installed') . ' from ' . shield_client_ip());
            // Move the session into HostShield's own session folder, used from now on.
            session_write_close();
            shield_session_start();
            shield_login($admin);
            flash(__('HostShield is installed. Set up the cron job below, then enable the firewall on your sites.'));
            go();
        }
    }
}

$found = !$installed ? shield_discover_sites() : [];
render_head(__('Install'));
?><body class="auth install">
<form method="post" class="auth-box wide">
    <div class="brand"><img src="assets/logo.svg" alt="" width="34" height="34"><span>HostShield</span></div>
    <h1><?= e($installed ? __('Create a new admin account') : __('Install HostShield')) ?></h1>
    <?php if ($err): ?><div class="alert err"><?= e($err) ?></div><?php endif; ?>
    <?php if ($configCode !== '' && $err !== ''): ?><pre class="log"><?= e($configCode) ?></pre><?php endif; ?>

    <?php if (!$unlocked): ?>
        <div class="alert warn">
            <b><?= e(__('Installer locked')) ?></b><br>
            <?= e($installed
                ? __('There is no admin account. To create one, make an empty file named install.unlock in %s (File Manager → New File), then reload this page.', $root)
                : __('For safety, the installer only runs in the first 24 hours after upload. Create an empty file named install.unlock in %s (File Manager → New File), then reload this page.', $root)) ?>
        </div>
    <?php else: ?>
        <?php if (!$installed): ?>
            <h2><?= e(__('1. Server check')) ?></h2>
            <ul class="req">
            <?php foreach ($checks as [$ok, $label, $note, $required]): ?>
                <li class="<?= $ok ? 'ok' : ($required ? 'bad' : 'warn') ?>"><span><?= $ok ? '✓' : ($required ? '✗' : '!') ?></span> <b><?= e($label) ?></b> <small class="muted"><?= e($note) ?></small></li>
            <?php endforeach; ?>
            </ul>
            <?php if ($blocking): ?>
                <div class="alert err"><?= e(__('Fix the items marked ✗ in your hosting panel (PHP version / PHP extensions), then reload.')) ?></div>
            <?php endif; ?>
        <?php endif; ?>

        <?php if (!$blocking): ?>
            <?= csrf_field() ?>
            <?php if (!$installed): ?>
                <h2><?= e(__('2. Data folder')) ?></h2>
                <?= field_text('data_dir', __('Where backups, logs and settings are stored'), (string)($_POST['data_dir'] ?? $suggestData),
                    e(__('Must be outside the web root, so nobody can download backups. The suggestion is next to the HostShield folder.'))) ?>
                <?php if ($docRoot !== '' && str_starts_with($suggestData . '/', $docRoot . '/')): ?>
                    <div class="alert warn"><?= e(__('The suggested folder is inside the web root. Choose a folder outside %s if you can.', $docRoot)) ?></div>
                <?php endif; ?>
            <?php endif; ?>

            <h2><?= e($installed ? __('Account') : __('3. Your account')) ?></h2>
            <div class="row2">
                <?= field_text('user', __('Username'), (string)($_POST['user'] ?? 'admin'), '', ['required' => true, 'autocomplete' => 'username']) ?>
                <?= $installed ? '' : field_text('email', __('Email for alerts'), (string)($_POST['email'] ?? ''), '', ['type' => 'email']) ?>
            </div>
            <div class="row2">
                <label class="field"><span><?= e(__('Password (min. 12 characters)')) ?></span><input type="password" name="password" minlength="12" required autocomplete="new-password"></label>
                <label class="field"><span><?= e(__('Repeat the password')) ?></span><input type="password" name="password2" minlength="12" required autocomplete="new-password"></label>
            </div>

            <?php if (!$installed): ?>
                <?= field_select('language', __('Language'), (string)($_POST['language'] ?? shield_lang()), SHIELD_LANGUAGES) ?>
                <input type="hidden" name="timezone" data-timezone value="">
                <h2><?= e(__('4. Sites to protect')) ?></h2>
                <?php if ($found): ?>
                    <p class="muted"><?= e(__('Found in this hosting account. You can add or remove sites later.')) ?></p>
                    <ul class="sites-pick">
                    <?php foreach ($found as $d): ?>
                        <li><label class="check"><input type="checkbox" name="paths[]" value="<?= e($d['path']) ?>" checked>
                            <span><b><?= e($d['domain'] ?: basename($d['path'])) ?></b> · <?= e(platform_label($d['platform'])) ?><?= $d['db'] ? ' · <span class="ok">' . e(__('database found')) . '</span>' : '' ?>
                            <small><code><?= e($d['path']) ?></code></small></span></label></li>
                    <?php endforeach; ?>
                    </ul>
                <?php else: ?>
                    <p class="muted"><?= e(__('No sites found automatically. Add them from the dashboard after installing.')) ?></p>
                <?php endif; ?>
            <?php endif; ?>

            <button class="btn primary wide"><?= e($installed ? __('Create account') : __('Install')) ?></button>
        <?php endif; ?>
    <?php endif; ?>
    <p class="muted center">HostShield <?= e(SHIELD_VERSION) ?> · <a href="https://github.com/<?= e(SHIELD_REPO) ?>" target="_blank" rel="noopener">GitHub</a></p>
</form>
</body></html>
