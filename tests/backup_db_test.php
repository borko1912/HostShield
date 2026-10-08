<?php
declare(strict_types=1);

// "Other databases": databases no site lists are still backed up. Needs MySQL:
//   SHIELD_TEST_DB="127.0.0.1:3306:root:secret" php tests/run.php other
$dsn = getenv('SHIELD_TEST_DB');
if ($dsn) {
    test('other databases: unassigned ones are dumped, assigned ones are not, restorable', function () use ($dsn): void {
        [$host, $port, $user, $pass] = array_pad(explode(':', $dsn, 4), 4, '');
        $root = new mysqli($host, $user, $pass, '', (int)$port);
        foreach (['hs_t_site', 'hs_t_orphan'] as $d) {
            $root->query("DROP DATABASE IF EXISTS `$d`");
            $root->query("CREATE DATABASE `$d`");
            $root->query("CREATE TABLE `$d`.t (id INT PRIMARY KEY, v VARCHAR(20))");
            $root->query("INSERT INTO `$d`.t VALUES (1, '$d')");
        }
        @mkdir($GLOBALS['t_tmp'] . '/site', 0700, true);
        $saved = shield_settings();
        $s = $saved;
        $s['db'] = ['host' => $host, 'port' => (int)$port, 'user' => $user, 'pass' => $pass];
        $s['sites']['t'] = ['path' => $GLOBALS['t_tmp'] . '/site', 'title' => 'T', 'databases' => ['hs_t_site']];
        shield_settings_save($s);
        shield_config(true);
        try {
            $visible = shield_visible_databases();
            ok(isset($visible['hs_t_site'], $visible['hs_t_orphan']), 'both test databases visible');
            ok(!isset($visible['mysql']) && !isset($visible['information_schema']), 'system schemas skipped');
            $extra = shield_unassigned_databases($visible);
            ok(isset($extra['hs_t_orphan']) && !isset($extra['hs_t_site']), 'only the database no site lists');

            $m = shield_backup_extra_databases('manual');
            ok($m !== null && in_array('hs_t_orphan', array_column($m['databases'], 'name'), true), 'orphan dumped');
            ok(!in_array('hs_t_site', array_column($m['databases'], 'name'), true), 'site database not duplicated');
            $list = shield_list_backups(SHIELD_EXTRA_DB_KEY);
            eq($m['name'], $list[0]['name'] ?? null, 'listed under ' . SHIELD_EXTRA_DB_KEY);
            eq([], shield_verify_backup($list[0]), 'verify without files.zip');

            $root->query('DROP TABLE hs_t_orphan.t');
            $file = $list[0]['dir'] . '/db-hs_t_orphan.sql.gz';
            shield_restore_database([], 'hs_t_orphan', $file);
            eq('hs_t_orphan', (string)$root->query('SELECT v FROM hs_t_orphan.t')->fetch_row()[0], 'restored from the dump');
        } finally {
            shield_settings_save($saved);
            shield_config(true);
            foreach (['hs_t_site', 'hs_t_orphan'] as $d) {
                $root->query("DROP DATABASE IF EXISTS `$d`");
            }
        }
    });
}
