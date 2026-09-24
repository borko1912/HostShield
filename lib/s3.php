<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

// S3-compatible storage client (AWS S3, Backblaze B2, Cloudflare R2, Wasabi, MinIO...).
// Signature Version 4, no SDK. Objects up to 5 GB (single PUT).

/** Authorization header value for an AWS Signature V4 request. */
function shield_sigv4(string $method, string $canonicalUri, array $query, array $headers, string $payloadHash,
    string $key, string $secret, string $region, string $amzDate, string $service = 's3'): string
{
    ksort($query, SORT_STRING);
    $cq = [];
    foreach ($query as $k => $v) {
        $cq[] = rawurlencode((string)$k) . '=' . rawurlencode((string)$v);
    }
    $h = [];
    foreach ($headers as $k => $v) {
        $h[strtolower((string)$k)] = trim((string)preg_replace('/\s+/', ' ', (string)$v));
    }
    ksort($h, SORT_STRING);
    $canonHeaders = '';
    foreach ($h as $k => $v) {
        $canonHeaders .= $k . ':' . $v . "\n";
    }
    $signed = implode(';', array_keys($h));
    $canonical = implode("\n", [$method, $canonicalUri, implode('&', $cq), $canonHeaders, $signed, $payloadHash]);
    $date = substr($amzDate, 0, 8);
    $scope = $date . '/' . $region . '/' . $service . '/aws4_request';
    $toSign = "AWS4-HMAC-SHA256\n" . $amzDate . "\n" . $scope . "\n" . hash('sha256', $canonical);
    $k = hash_hmac('sha256', $date, 'AWS4' . $secret, true);
    $k = hash_hmac('sha256', $region, $k, true);
    $k = hash_hmac('sha256', $service, $k, true);
    $k = hash_hmac('sha256', 'aws4_request', $k, true);
    $sig = hash_hmac('sha256', $toSign, $k);
    return 'AWS4-HMAC-SHA256 Credential=' . $key . '/' . $scope . ', SignedHeaders=' . $signed . ', Signature=' . $sig;
}

function shield_s3_cfg(?array $c = null): array
{
    $c ??= (array)shield_config()['backup']['offsite']['s3'];
    foreach (['endpoint', 'bucket', 'key', 'secret'] as $k) {
        if (trim((string)($c[$k] ?? '')) === '') {
            throw new RuntimeException('S3: ' . $k . ' is not set');
        }
    }
    $c['endpoint'] = rtrim((string)$c['endpoint'], '/');
    if (!preg_match('#^https?://#', $c['endpoint'])) {
        $c['endpoint'] = 'https://' . $c['endpoint'];
    }
    $c['region'] = trim((string)($c['region'] ?? '')) ?: 'auto';
    $c['prefix'] = ltrim((string)($c['prefix'] ?? ''), '/');
    return $c;
}

/**
 * One S3 request. $o: query (array), body (string), infile (path), sink (path).
 * Returns shield_http() result.
 */
function shield_s3_request(string $method, string $objectKey, array $o = [], ?array $cfg = null): array
{
    $c = shield_s3_cfg($cfg);
    $host = (string)parse_url($c['endpoint'], PHP_URL_HOST);
    $port = parse_url($c['endpoint'], PHP_URL_PORT);
    $scheme = (string)parse_url($c['endpoint'], PHP_URL_SCHEME);
    $basePath = rtrim((string)parse_url($c['endpoint'], PHP_URL_PATH), '/');
    $keyPath = implode('/', array_map('rawurlencode', explode('/', ltrim($objectKey, '/'))));
    if (!empty($c['path_style'])) {
        $uri = $basePath . '/' . rawurlencode((string)$c['bucket']) . ($keyPath !== '' ? '/' . $keyPath : ($objectKey === '' ? '/' : ''));
    } else {
        $host = $c['bucket'] . '.' . $host;
        $uri = $basePath . '/' . $keyPath;
    }
    $hostHeader = $host . ($port ? ':' . $port : '');
    $query = (array)($o['query'] ?? []);
    if (isset($o['infile'])) {
        $payload = hash_file('sha256', (string)$o['infile']);
    } else {
        $payload = hash('sha256', (string)($o['body'] ?? ''));
    }
    $amzDate = gmdate('Ymd\THis\Z');
    $headers = ['host' => $hostHeader, 'x-amz-content-sha256' => $payload, 'x-amz-date' => $amzDate];
    $auth = shield_sigv4($method, $uri, $query, $headers, $payload, (string)$c['key'], (string)$c['secret'], $c['region'], $amzDate);
    $qs = [];
    ksort($query, SORT_STRING);
    foreach ($query as $k => $v) {
        $qs[] = rawurlencode((string)$k) . '=' . rawurlencode((string)$v);
    }
    $url = $scheme . '://' . $hostHeader . $uri . ($qs ? '?' . implode('&', $qs) : '');
    $http = [
        'method' => $method, 'follow' => false, 'timeout' => (int)($o['timeout'] ?? 120),
        'headers' => ['Authorization: ' . $auth, 'x-amz-content-sha256: ' . $payload, 'x-amz-date: ' . $amzDate, 'Expect:'],
    ];
    foreach (['body', 'infile', 'sink'] as $k) {
        if (isset($o[$k])) {
            $http[$k] = $o[$k];
        }
    }
    if ($method === 'PUT' && !isset($o['infile']) && !isset($o['body'])) {
        $http['body'] = '';
    }
    return shield_http($url, $http);
}

function shield_s3_error(array $r): string
{
    if (preg_match('#<Code>(.*?)</Code>.*?<Message>(.*?)</Message>#s', $r['body'], $m)) {
        return $m[1] . ': ' . html_entity_decode($m[2]);
    }
    return 'HTTP ' . $r['code'] . ($r['error'] ? ' ' . $r['error'] : '');
}

function shield_s3_put_file(string $key, string $file, ?array $cfg = null): void
{
    if (filesize($file) > 5 * 1024 ** 3) {
        throw new RuntimeException('S3: ' . basename($file) . ' is larger than 5 GB');
    }
    $r = shield_s3_request('PUT', $key, ['infile' => $file, 'timeout' => 3600], $cfg);
    if ($r['code'] !== 200) {
        throw new RuntimeException('S3 upload ' . $key . ': ' . shield_s3_error($r));
    }
}

function shield_s3_put(string $key, string $body, ?array $cfg = null): void
{
    $r = shield_s3_request('PUT', $key, ['body' => $body], $cfg);
    if ($r['code'] !== 200) {
        throw new RuntimeException('S3 upload ' . $key . ': ' . shield_s3_error($r));
    }
}

function shield_s3_get_file(string $key, string $dest, ?array $cfg = null): void
{
    $r = shield_s3_request('GET', $key, ['sink' => $dest, 'timeout' => 3600], $cfg);
    if ($r['code'] !== 200) {
        $err = is_file($dest) ? (string)file_get_contents($dest, false, null, 0, 2000) : '';
        @unlink($dest);
        throw new RuntimeException('S3 download ' . $key . ': ' . shield_s3_error(['code' => $r['code'], 'body' => $err, 'error' => $r['error']]));
    }
}

function shield_s3_get(string $key, ?array $cfg = null): ?string
{
    $r = shield_s3_request('GET', $key, [], $cfg);
    return $r['code'] === 200 ? $r['body'] : null;
}

function shield_s3_delete(string $key, ?array $cfg = null): void
{
    $r = shield_s3_request('DELETE', $key, [], $cfg);
    if ($r['code'] !== 204 && $r['code'] !== 200) {
        throw new RuntimeException('S3 delete ' . $key . ': ' . shield_s3_error($r));
    }
}

/** Lists keys (and common prefixes when a delimiter is given) under a prefix. */
function shield_s3_list(string $prefix, ?string $delimiter = null, ?array $cfg = null): array
{
    $keys = [];
    $prefixes = [];
    $token = null;
    do {
        $q = ['list-type' => '2', 'prefix' => $prefix];
        if ($delimiter !== null) {
            $q['delimiter'] = $delimiter;
        }
        if ($token !== null) {
            $q['continuation-token'] = $token;
        }
        $r = shield_s3_request('GET', '', ['query' => $q], $cfg);
        if ($r['code'] !== 200) {
            throw new RuntimeException('S3 list: ' . shield_s3_error($r));
        }
        $x = @simplexml_load_string($r['body']);
        if ($x === false) {
            throw new RuntimeException('S3 list: invalid response');
        }
        foreach ($x->Contents as $o) {
            $keys[(string)$o->Key] = (int)$o->Size;
        }
        foreach ($x->CommonPrefixes as $p) {
            $prefixes[] = (string)$p->Prefix;
        }
        $token = (string)$x->IsTruncated === 'true' ? (string)$x->NextContinuationToken : null;
    } while ($token !== null && $token !== '');
    return ['keys' => $keys, 'prefixes' => $prefixes];
}
