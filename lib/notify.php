<?php
declare(strict_types=1);

require_once __DIR__ . '/core.php';

// Notifications: email (PHP mail() or SMTP), Telegram and a chat webhook (Discord, Slack or generic JSON).
// Every alert goes to every configured channel, if its event type is switched on.

const SHIELD_EVENTS = [
    'backup_failed' => 'Backup failed',
    'malware' => 'Suspicious code found',
    'changes' => 'Files changed',
    'down' => 'Site down / back up',
    'ban' => 'Attackers banned (hourly digest)',
    'login' => 'Dashboard logins',
    'restore' => 'Restore finished',
    'audit' => 'New security audit problems',
    'ssl' => 'SSL certificate expiring',
    'update' => 'New Shield version',
];

/** Sends an alert. Returns the list of channels that accepted it. */
function shield_notify(string $event, string $subject, string $body): array
{
    $n = (array)(shield_config()['notify'] ?? []);
    if (isset(SHIELD_EVENTS[$event]) && empty($n['events'][$event])) {
        return [];
    }
    $sent = [];
    $channels = [
        'email' => static fn() => shield_mail($subject, $body),
        'telegram' => static fn() => shield_telegram($subject, $body),
        'webhook' => static fn() => shield_webhook($subject, $body),
    ];
    foreach ($channels as $name => $fn) {
        if (!shield_channel_configured($name)) {
            continue;
        }
        try {
            if ($fn()) {
                $sent[] = $name;
            }
        } catch (Throwable $e) {
            shield_log('notify', $name . ' ERROR: ' . $e->getMessage());
        }
    }
    shield_log('notify', '[' . $event . '] ' . $subject . ' → ' . ($sent ? implode(', ', $sent) : 'nobody'));
    return $sent;
}

function shield_channel_configured(string $name): bool
{
    $n = (array)(shield_config()['notify'] ?? []);
    return match ($name) {
        'email' => trim((string)($n['email'] ?? '')) !== '',
        'telegram' => trim((string)($n['telegram']['token'] ?? '')) !== '' && trim((string)($n['telegram']['chat_id'] ?? '')) !== '',
        'webhook' => trim((string)($n['webhook']['url'] ?? '')) !== '',
        default => false,
    };
}

function shield_site_label(): string
{
    return parse_url(shield_dashboard_url(), PHP_URL_HOST) ?: 'HostShield';
}

// --------------------------------------------------------------------------- email

function shield_mail(string $subject, string $body): bool
{
    $n = (array)shield_config()['notify'];
    $to = trim((string)($n['email'] ?? ''));
    if ($to === '') {
        return false;
    }
    if (($n['transport'] ?? 'mail') === 'smtp') {
        return shield_smtp_send($to, $subject, $body);
    }
    // On many shared hosts mail() from cron/CLI never arrives; the dashboard (PHP-FPM) sends it instead.
    if (PHP_SAPI === 'cli' && shield_config()['dashboard_url'] !== '') {
        return shield_mail_relay($subject, $body);
    }
    return shield_mail_send($to, $subject, $body);
}

function shield_mail_from(): string
{
    $from = trim((string)(shield_config()['notify']['mail_from'] ?? ''));
    if ($from === '') {
        $host = (string)(parse_url(shield_dashboard_url(), PHP_URL_HOST) ?: 'localhost');
        $from = 'shield@' . preg_replace('/^www\./', '', $host);
    }
    return $from;
}

function shield_mail_body(string $body): string
{
    return $body . "\n\n— HostShield " . SHIELD_VERSION . ' · ' . date('Y-m-d H:i') . "\n" . shield_dashboard_url();
}

function shield_mail_send(string $to, string $subject, string $body): bool
{
    $from = shield_mail_from();
    $headers = [
        'From: HostShield <' . $from . '>',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
    ];
    return @mail($to, '=?UTF-8?B?' . base64_encode('[Shield] ' . $subject) . '?=', shield_mail_body($body), implode("\r\n", $headers), '-f' . $from);
}

function shield_mail_relay(string $subject, string $body): bool
{
    $r = shield_http(shield_dashboard_url() . '/?p=relay-mail', [
        'method' => 'POST', 'timeout' => 30,
        // base64 so the firewall does not flag alert text such as "' or 1=1".
        'body' => http_build_query(['token' => shield_relay_token(), 's' => base64_encode($subject), 'b' => base64_encode($body)]),
    ]);
    if ($r['code'] === 200 && trim($r['body']) === 'OK') {
        return true;
    }
    shield_log('mail', "Relay failed ({$r['code']} {$r['error']}), trying mail() directly");
    return shield_mail_send((string)shield_config()['notify']['email'], $subject, $body);
}

/** Minimal SMTP client: SSL (465) or STARTTLS (587), AUTH LOGIN. */
function shield_smtp_send(string $to, string $subject, string $body): bool
{
    $s = (array)shield_config()['notify']['smtp'];
    $host = (string)$s['host'];
    $port = (int)($s['port'] ?? 587);
    $secure = (string)($s['secure'] ?? 'tls');
    $fp = @stream_socket_client(($secure === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port, $errno, $errstr, 20);
    if (!$fp) {
        throw new RuntimeException("SMTP connect {$host}:{$port} failed: {$errstr}");
    }
    stream_set_timeout($fp, 30);
    $read = static function () use ($fp): array {
        $data = '';
        while (($line = fgets($fp, 1024)) !== false) {
            $data .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') {
                break;
            }
        }
        return [(int)substr($data, 0, 3), trim($data)];
    };
    $cmd = static function (string $c, array $ok) use ($fp, $read): string {
        fwrite($fp, $c . "\r\n");
        [$code, $msg] = $read();
        if (!in_array($code, $ok, true)) {
            $shown = str_starts_with($c, 'AUTH') || strlen($c) > 60 ? strtok($c, ' ') : $c;
            throw new RuntimeException("SMTP {$shown}: {$msg}");
        }
        return $msg;
    };
    try {
        [$code, $msg] = $read();
        if ($code !== 220) {
            throw new RuntimeException('SMTP greeting: ' . $msg);
        }
        $me = gethostname() ?: 'localhost';
        $cmd('EHLO ' . $me, [250]);
        if ($secure === 'tls') {
            $cmd('STARTTLS', [220]);
            if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT)) {
                throw new RuntimeException('SMTP STARTTLS failed');
            }
            $cmd('EHLO ' . $me, [250]);
        }
        if ((string)($s['user'] ?? '') !== '') {
            $cmd('AUTH LOGIN', [334]);
            $cmd(base64_encode((string)$s['user']), [334]);
            $cmd(base64_encode((string)$s['pass']), [235]);
        }
        $from = shield_mail_from();
        $cmd('MAIL FROM:<' . $from . '>', [250]);
        foreach (array_filter(array_map('trim', explode(',', $to))) as $rcpt) {
            $cmd('RCPT TO:<' . $rcpt . '>', [250, 251]);
        }
        $cmd('DATA', [354]);
        $msg = implode("\r\n", [
            'From: HostShield <' . $from . '>',
            'To: ' . $to,
            'Subject: =?UTF-8?B?' . base64_encode('[Shield] ' . $subject) . '?=',
            'Date: ' . date('r'),
            'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . (explode('@', $from)[1] ?? 'localhost') . '>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: base64',
            '',
            rtrim(chunk_split(base64_encode(shield_mail_body($body)), 76, "\r\n")),
        ]);
        $cmd($msg . "\r\n.", [250]);
        fwrite($fp, "QUIT\r\n");
        return true;
    } finally {
        fclose($fp);
    }
}

// --------------------------------------------------------------------------- chat

function shield_telegram(string $subject, string $body): bool
{
    $t = (array)shield_config()['notify']['telegram'];
    $text = '🛡 *' . shield_md_escape($subject) . "*\n" . shield_md_escape(mb_substr($body, 0, 3500)) . "\n_" . shield_md_escape(shield_site_label()) . '_';
    $r = shield_http('https://api.telegram.org/bot' . rawurlencode((string)$t['token']) . '/sendMessage', [
        'method' => 'POST', 'timeout' => 20, 'headers' => ['Content-Type: application/json'],
        'body' => json_encode(['chat_id' => (string)$t['chat_id'], 'text' => $text, 'parse_mode' => 'MarkdownV2', 'disable_web_page_preview' => true]),
    ]);
    if ($r['code'] !== 200) {
        throw new RuntimeException('Telegram ' . $r['code'] . ': ' . mb_substr($r['body'] ?: $r['error'], 0, 200));
    }
    return true;
}

function shield_md_escape(string $s): string
{
    return (string)preg_replace('/([_*\[\]()~`>#+\-=|{}.!\\\\])/', '\\\\$1', $s);
}

function shield_webhook(string $subject, string $body): bool
{
    $w = (array)shield_config()['notify']['webhook'];
    $text = '🛡 ' . $subject . "\n" . mb_substr($body, 0, 1800);
    $payload = match ((string)($w['format'] ?? 'discord')) {
        'discord' => ['username' => 'HostShield', 'content' => $text],
        'slack' => ['text' => $text],
        default => ['source' => 'hostshield', 'host' => shield_site_label(), 'subject' => $subject, 'body' => $body, 'time' => date('c')],
    };
    $r = shield_http((string)$w['url'], [
        'method' => 'POST', 'timeout' => 20, 'headers' => ['Content-Type: application/json'],
        'body' => json_encode($payload, JSON_UNESCAPED_UNICODE),
    ]);
    if ($r['code'] < 200 || $r['code'] >= 300) {
        throw new RuntimeException('Webhook ' . $r['code'] . ': ' . mb_substr($r['body'] ?: $r['error'], 0, 200));
    }
    return true;
}
