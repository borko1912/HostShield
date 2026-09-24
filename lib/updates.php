<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

/** Latest release on GitHub, checked at most twice a day. Returns ['version', 'url', 'notes'] or []. */
function shield_update_check(bool $force = false): array
{
    if (empty(shield_config()['updates']['check'])) {
        return [];
    }
    $file = shield_path('cache/update.json');
    $c = shield_json_read($file);
    if (!$force && time() - (int)($c['checked'] ?? 0) < 43200) {
        return (array)($c['release'] ?? []);
    }
    $r = shield_http('https://api.github.com/repos/' . SHIELD_REPO . '/releases/latest', ['timeout' => 15, 'headers' => ['Accept: application/vnd.github+json']]);
    $release = [];
    if ($r['code'] === 200 && ($d = json_decode($r['body'], true))) {
        $release = ['version' => ltrim((string)$d['tag_name'], 'v'), 'url' => (string)$d['html_url'], 'notes' => mb_substr((string)($d['body'] ?? ''), 0, 2000)];
    }
    shield_json_write($file, ['checked' => time(), 'release' => $release]);
    return $release;
}

function shield_update_available(): ?array
{
    $r = shield_update_check();
    return $r && version_compare($r['version'], SHIELD_VERSION, '>') ? $r : null;
}
