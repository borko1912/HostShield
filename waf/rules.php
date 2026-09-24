<?php
// HostShield — firewall rule set.
// Loaded on every request (opcache keeps it in memory). Each pattern runs against
// normalized request values: lowercased, URL-decoded twice, HTML entities decoded,
// inline SQL comments removed.

return [
    // Automated scanners and attack tools (matched in the User-Agent).
    'scanner_ua' => ['sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab', 'wpscan', 'acunetix', 'nessus', 'netsparker',
        'dirbuster', 'gobuster', 'ffuf', 'nuclei', 'jaeles', 'havij', 'commix', 'w3af', 'openvas', 'zmeu', 'fuzz faster',
        'feroxbuster', 'whatweb', 'wfuzz', 'hydra', 'arachni', 'skipfish', 'xsstrike', 'dotdotpwn', 'joomscan', 'droopescan'],

    // Paths that only attackers request. Substring match on the lowercased path.
    'probes' => ['/wp-config', '/.env', '/.git/', '/.git', '/.svn', '/.hg/', '/.aws', '/.ssh', '/.htpasswd', '/phpmyadmin',
        '/pma/', '/myadmin', '/vendor/phpunit', 'eval-stdin.php', '/cgi-bin/', '/boaform', '/actuator', '/.ds_store', '/adminer',
        '/server-status', '/alfa', '/wso', '/shell.php', '/c99.php', '/r57.php', '/owa/', '/solr/', '/hnap1', '/console/',
        '/telescope', '/_ignition', '/.vscode', '/sftp-config.json', '/backup.zip', '/backup.sql', '/dump.sql', '/db.sql',
        '/database.sql', '/phpinfo.php', '/info.php', '/.idea/', '/web.config.bak', '/config.php.bak', '/wp-config.php.bak'],

    // WordPress paths: normal on WordPress sites, a probe everywhere else.
    'wp_paths' => ['/wp-login.php', '/wp-admin', '/wp-content', '/wp-includes', '/xmlrpc.php', '/wlwmanifest.xml'],

    // Content rules: id => [regex, category, description].
    'patterns' => [
        'sqli_union'   => ['/\bunion\b(\s+all|\s+distinct)?\s*\(?\s*select\b/', 'sqli', 'SQL injection: UNION SELECT'],
        'sqli_schema'  => ['/\binformation_schema\b|\bmysql\.user\b|\bsys\.schema/', 'sqli', 'SQL injection: schema enumeration'],
        'sqli_time'    => ['/\b(sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b/', 'sqli', 'SQL injection: time-based'],
        'sqli_file'    => ['/\bload_file\s*\(|\binto\s+(out|dump)file\b/', 'sqli', 'SQL injection: file read/write'],
        'sqli_bool'    => ["/['\"`]\\s*(or|and|\\|\\||&&)\\s*['\"`]?[\\w]+['\"`]?\\s*(=|like)\\s*['\"`]?[\\w]+|['\"`]\\s*(or|and)\\s+\\d+\\s*(=|<|>)\\s*\\d+/", 'sqli', 'SQL injection: boolean condition'],
        'sqli_comment' => ["/['\"`)]\\s*;?\\s*(--|#)\\s*$|\\/\\*!\\d*/", 'sqli', 'SQL injection: comment truncation'],
        'sqli_stacked' => ['/;\s*(drop|truncate|alter|create|rename)\s+(table|database)\b|;\s*shutdown\b/', 'sqli', 'SQL injection: stacked query'],
        'sqli_error'   => ['/\b(extractvalue|updatexml|exp\(~|geometrycollection|polygon)\s*\(/', 'sqli', 'SQL injection: error-based'],
        'xss_script'   => ['/<\s*\/?\s*script\b|<\s*iframe\b|<\s*(object|embed|base|meta)\b[^>]*>/', 'xss', 'XSS: script or frame tag'],
        'xss_event'    => ['/<[^>]+\bon[a-z]{3,20}\s*=|\bjavascript\s*:|\bvbscript\s*:|<\s*svg[^>]*\bon|\bsrcdoc\s*=/', 'xss', 'XSS: event handler or javascript: URL'],
        'traversal'    => ['/(\.\.[\/\\\\]){2,}|\/etc\/(passwd|shadow|group|hosts)\b|c:\\\\windows\\\\|\/proc\/self\//', 'lfi', 'Path traversal / local file read'],
        'wrapper'      => ['/\b(php|phar|expect|zip|glob|data):\/\//', 'lfi', 'PHP stream wrapper'],
        'php_code'     => ['/<\?php|\b(eval|assert|system|passthru|shell_exec|proc_open|popen|pcntl_exec|base64_decode|gzinflate|str_rot13|create_function|call_user_func)\(/', 'rce', 'PHP code injection'],
        'cmd_inject'   => ['/(;|\||`|\$\(|&&)\s*(wget|curl|bash|sh|nc|ncat|python\d?|perl|php|chmod|rm\s+-|cat\s+\/|id;|uname|whoami)\b/', 'rce', 'OS command injection'],
        'log4j'        => ['/\$\{\s*(jndi|lower|upper|env|sys)\s*:/', 'rce', 'Log4Shell (JNDI lookup)'],
        'shellshock'   => ['/\(\)\s*\{\s*:\s*;\s*\}\s*;/', 'rce', 'Shellshock'],
        'ssti'         => ['/\{\{\s*[\w.]*(__class__|constructor|self\.|config\.|request\.)/', 'rce', 'Server-side template injection'],
        'php_object'   => ['/\bo:\d+:"[a-z_\\\\][a-z0-9_\\\\]*":\d+:\{/', 'rce', 'PHP object injection (serialized object)'],
        'xxe'          => ['/<!entity[^>]+\bsystem\b/', 'xxe', 'XML external entity'],
        'ssrf_meta'    => ['/\b169\.254\.169\.254\b|metadata\.google\.internal|\bfd00:ec2::254\b/', 'ssrf', 'SSRF to cloud metadata'],
    ],

    // Rules raised outside the content patterns (for the dashboard).
    'other' => [
        'scanner_ua'       => ['scan', 'Attack tool / vulnerability scanner'],
        'probe'            => ['scan', 'Probe for a sensitive file or admin tool'],
        'null_byte'        => ['lfi', 'Null byte in request'],
        'upload_script'    => ['upload', 'Upload of an executable script'],
        'upload_php_code'  => ['upload', 'Upload with embedded PHP code'],
        'exec_in_uploads'  => ['rce', 'PHP executed from an upload folder'],
        'exec_not_allowed' => ['rce', 'Script not on the approved list (Lockdown)'],
        'wp_xmlrpc'        => ['wordpress', 'WordPress XML-RPC blocked'],
        'wp_user_enum'     => ['wordpress', 'WordPress user enumeration'],
        'login_bruteforce' => ['bruteforce', 'Too many login attempts'],
        'rate_limit'       => ['flood', 'Too many requests'],
        'blocklist'        => ['list', 'IP on the block list'],
    ],

    // Uploaded file names that must never be accepted.
    'upload_ext' => '/\.(php\d?|phtml|phar|pht|phps|pgif|shtml|cgi|pl|py|sh|asp|aspx|jsp|htaccess)(\.|$)|^\.user\.ini$|^\.htaccess$/',

    // POST field names that mark a login attempt.
    'login_fields' => '/pass|парола|pwd/i',
];
