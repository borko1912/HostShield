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
    // 404 means "no release published yet", not a network problem.
    $status = $r['code'] === 404 ? 'none' : 'error';
    if ($r['code'] === 200 && ($d = json_decode($r['body'], true))) {
        $release = ['version' => ltrim((string)$d['tag_name'], 'v'), 'url' => (string)$d['html_url'], 'notes' => mb_substr((string)($d['body'] ?? ''), 0, 2000)];
        $status = 'ok';
    }
    shield_json_write($file, ['checked' => time(), 'release' => $release, 'status' => $status]);
    return $release;
}

/** Result of the last check: ok | none (no release yet) | error (GitHub unreachable) | disabled. */
function shield_update_status(): string
{
    if (empty(shield_config()['updates']['check'])) {
        return 'disabled';
    }
    return (string)(shield_json_read(shield_path('cache/update.json'))['status'] ?? 'error');
}

/** Newer release than this one, or null. The dashboard only reads the cache; the worker refreshes it. */
function shield_update_available(bool $fetch = false): ?array
{
    $r = $fetch ? shield_update_check() : (array)(shield_json_read(shield_path('cache/update.json'))['release'] ?? []);
    return $r && version_compare($r['version'], SHIELD_VERSION, '>') ? $r : null;
}
