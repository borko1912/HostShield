<?php
// File integrity: baseline, change detection, approval, quarantine.

test('integrity: baseline, changes, approve, quarantine', function (): void {
    $path = $GLOBALS['t_tmp'] . '/sites/mon';
    @mkdir($path . '/uploads', 0777, true);
    file_put_contents($path . '/index.php', "<?php echo 'home';\n");
    file_put_contents($path . '/uploads/photo.jpg', "\xFF\xD8\xFFjpeg");

    $s = shield_settings();
    $s['sites']['mon'] = ['path' => $path, 'title' => 'Mon', 'upload_dirs' => ['uploads']];
    shield_settings_save($s);

    $r = shield_integrity_check('mon', false);
    eq(1, $r['files_watched'], 'code files');
    eq(1, $r['uploads_watched'], 'upload files');
    eq([], array_keys($r['malware']), 'clean at start');
    ok(is_file(shield_path('waf/exec-mon.php')), 'lockdown allowlist written');
    eq(['index.php' => 1], include shield_path('waf/exec-mon.php'));

    file_put_contents($path . '/index.php', "<?php echo 'home v2';\n");
    file_put_contents($path . '/about.php', "<?php echo 'about';\n");
    file_put_contents($path . '/uploads/note.php', "<?php echo 1;\n");
    $r = shield_integrity_check('mon', false);
    ok(isset($r['modified']['index.php']), 'modified detected');
    ok(isset($r['added']['about.php']), 'added detected');
    ok(isset($r['malware']['uploads/note.php']), 'PHP in uploads flagged');
    eq('high', $r['malware']['uploads/note.php']['level'] ?? null);

    $id = shield_quarantine_file('mon', 'uploads/note.php', ['code_in_uploads']);
    ok(!is_file($path . '/uploads/note.php'), 'file moved out');
    eq(1, count(shield_quarantine_list('mon')));
    eq('uploads/note.php', shield_quarantine_restore('mon', $id));
    ok(is_file($path . '/uploads/note.php'), 'file put back');
    unlink($path . '/uploads/note.php');

    $r = shield_integrity_accept('mon');
    eq([], $r['added'] + $r['modified'] + $r['removed'], 'approved');
    eq(['about.php' => 1, 'index.php' => 1], (function () { $a = include shield_path('waf/exec-mon.php'); ksort($a); return $a; })());

    file_put_contents($path . '/uploads/photo2.jpg', "\xFF\xD8\xFFmore");
    $r = shield_integrity_check('mon', false);
    eq([], $r['added'], 'new uploads are not reported as changes');

    $s = shield_settings();
    unset($s['sites']['mon']);
    shield_settings_save($s);
});

test('scanner: normal code is clean', function (): void {
    $dir = $GLOBALS['t_tmp'] . '/scan';
    @mkdir($dir, 0777, true);
    $samples = [
        'a.php' => "<?php\nfunction add(int \$a, int \$b): int { return \$a + \$b; }\necho json_encode(['ok' => true]);\n",
        'b.php' => "<?php\n\$data = base64_encode(file_get_contents(__FILE__));\n\$img = '<img src=\"data:image/png;base64,iVBORw0KGgo=\">';\n",
        '.htaccess' => "Options -Indexes\nRewriteEngine On\nRewriteRule ^(.*)$ index.php [L]\n",
        'app.js' => "document.querySelector('#x').addEventListener('click', () => console.log('hi'));\n",
        'README.md' => "Use <?php echo 1; ?> in templates.\n",
    ];
    foreach ($samples as $n => $c) {
        file_put_contents($dir . '/' . $n, $c);
        eq([], shield_scan_file($dir . '/' . $n, false), $n);
    }
    file_put_contents($dir . '/.user.ini', 'auto_prepend_file = "/home/u/hostshield/waf/firewall.php"' . "\n");
    eq([], shield_scan_file($dir . '/.user.ini', false), 'our own prepend line is fine');
});
