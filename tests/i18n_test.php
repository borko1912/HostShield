<?php
// Every translatable string in the code has a Bulgarian translation.

test('i18n: Bulgarian covers every string', function (): void {
    $bg = require dirname(__DIR__) . '/lang/bg.php';
    $root = str_replace('\\', '/', dirname(__DIR__));
    $missing = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $f) {
        $rel = substr(str_replace('\\', '/', $f->getPathname()), strlen($root) + 1);
        if ($f->getExtension() !== 'php' || preg_match('#^(tests|lang|vendor|\.git)/#', $rel)) {
            continue;
        }
        preg_match_all("/__\(\s*'((?:[^'\\\\]|\\\\.)*)'/", (string)file_get_contents($f->getPathname()), $m);
        foreach ($m[1] as $s) {
            $s = str_replace(["\\'", '\\\\'], ["'", '\\'], $s);
            if (!isset($bg[$s])) {
                $missing[] = $rel . ': ' . $s;
            }
        }
    }
    eq([], array_values(array_unique($missing)), 'untranslated');
    foreach ($bg as $en => $tr) {
        preg_match_all('/%0?\d*[sdf]/', $en, $a);
        preg_match_all('/%0?\d*[sdf]/', $tr, $b);
        ok($a[0] === $b[0], 'placeholders: ' . $en);
    }
});
