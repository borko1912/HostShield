<?php
declare(strict_types=1);

// Test runner without dependencies: php tests/run.php [filter]
// Integration tests that need MySQL run when SHIELD_TEST_DB is set, e.g.
//   SHIELD_TEST_DB="127.0.0.1:3306:root:secret" php tests/run.php

error_reporting(E_ALL);
ini_set('display_errors', '1');
set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
    throw new ErrorException($msg, 0, $no, $file, $line);
});

$GLOBALS['t_pass'] = 0;
$GLOBALS['t_fail'] = [];
$GLOBALS['t_current'] = '';

function test(string $name, callable $fn): void
{
    global $argv;
    $filter = $argv[1] ?? '';
    if ($filter !== '' && !str_contains($name, $filter)) {
        return;
    }
    $GLOBALS['t_current'] = $name;
    try {
        $fn();
    } catch (Throwable $e) {
        $GLOBALS['t_fail'][] = $name . ': ' . get_class($e) . ': ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine();
    }
}

function ok(bool $cond, string $what = ''): void
{
    if ($cond) {
        $GLOBALS['t_pass']++;
        return;
    }
    $GLOBALS['t_fail'][] = $GLOBALS['t_current'] . ($what !== '' ? ' — ' . $what : '');
}

function eq(mixed $expected, mixed $actual, string $what = ''): void
{
    ok($expected === $actual, ($what !== '' ? $what . ': ' : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
}

// A throw-away installation for the code under test.
$tmp = sys_get_temp_dir() . '/hostshield-test-' . getmypid();
@mkdir($tmp . '/data', 0700, true);
file_put_contents($tmp . '/config.php', "<?php return ['data_dir' => " . var_export(str_replace('\\', '/', $tmp . '/data'), true) . "];");
putenv('SHIELD_CONFIG=' . $tmp . '/config.php');
define('SHIELD_QUIET', true);
$GLOBALS['t_tmp'] = str_replace('\\', '/', $tmp);

require_once dirname(__DIR__) . '/lib/core.php';
require_once dirname(__DIR__) . '/lib/auth.php';
require_once dirname(__DIR__) . '/lib/backup.php';
require_once dirname(__DIR__) . '/lib/monitor.php';
require_once dirname(__DIR__) . '/lib/detect.php';
require_once dirname(__DIR__) . '/lib/s3.php';
shield_lang('en');

foreach (glob(__DIR__ . '/*_test.php') as $f) {
    require $f;
}

// cleanup
$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($tmp, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
foreach ($it as $f) {
    $f->isDir() ? @rmdir($f->getPathname()) : @unlink($f->getPathname());
}
@rmdir($tmp);

$fails = $GLOBALS['t_fail'];
echo "\n" . $GLOBALS['t_pass'] . ' assertions passed, ' . count($fails) . " failed\n";
foreach ($fails as $f) {
    echo "  ✗ {$f}\n";
}
exit($fails ? 1 : 0);
