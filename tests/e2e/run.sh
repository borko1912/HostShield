#!/usr/bin/env bash
# HostShield end-to-end test.
# Starts WordPress + MariaDB + MinIO in Docker, installs HostShield through its web installer
# and checks backup, restore, firewall, scanner, quarantine, off-site storage and audit.
#
#   bash tests/e2e/run.sh          # run and tear down
#   KEEP=1 bash tests/e2e/run.sh   # leave the containers running (http://127.0.0.1:8090/hostshield/)

set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
BASE="http://127.0.0.1:8090"
JAR="$(mktemp)"
PASS=0
FAIL=0

dc() { docker compose -f docker-compose.yml "$@"; }
web() { dc exec -T web bash -c "$1"; }
www() { dc exec -T -u www-data web bash -c "$1"; }
shield_php() { www "cd /var/www/hostshield && php -r '$1'"; }
check() { # check "name" <command...>
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); echo "  ✓ $name"; else FAIL=$((FAIL + 1)); echo "  ✗ $name"; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
csrf() { curl -s -b "$JAR" -c "$JAR" "$1" | sed -n 's/.*name="csrf" value="\([0-9a-f]*\)".*/\1/p' | head -1; }
cleanup() { rm -f "$JAR"; [ "${KEEP:-}" = "1" ] || dc down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "== Starting containers"
dc up -d >/dev/null 2>&1 || { dc up -d; exit 1; }
for i in $(seq 1 60); do [ "$(code "$BASE/wp-admin/install.php")" = "200" ] && break; sleep 2; done

echo "== Installing WordPress"
curl -s -o /dev/null "$BASE/wp-admin/install.php?step=2" \
    --data-urlencode "weblog_title=HostShield E2E" --data-urlencode "user_name=wpadmin" \
    --data-urlencode "admin_password=e2e-Admin-password-1" --data-urlencode "admin_password2=e2e-Admin-password-1" \
    --data-urlencode "pw_weak=1" --data-urlencode "admin_email=admin@example.com" --data-urlencode "blog_public=0"
check "WordPress installed" test "$(code "$BASE/")" = "200"

echo "== Deploying HostShield"
(cd "$ROOT" && git ls-files -co --exclude-standard -- . ':!tests' ':!docs' ':!config.php' | tar -cf - -T -) | dc exec -T web bash -c 'mkdir -p /var/www/hostshield && tar -xf - -C /var/www/hostshield'
web 'mkdir -p /var/www/hostshield-data && chown -R www-data:www-data /var/www/hostshield /var/www/hostshield-data
     printf "Alias /hostshield /var/www/hostshield\n<Directory /var/www/hostshield>\n  AllowOverride All\n  Require all granted\n</Directory>\n" > /etc/apache2/conf-enabled/hostshield.conf
     # WordPress lives at 127.0.0.1:8090 (its site URL); make that address work inside the container too.
     grep -q "Listen 8090" /etc/apache2/ports.conf || printf "Listen 8090\n<VirtualHost *:8090>\n  DocumentRoot /var/www/html\n</VirtualHost>\n" >> /etc/apache2/ports.conf
     a2enmod headers rewrite >/dev/null; apache2ctl graceful'
sleep 2

echo "== Web installer"
TOKEN="$(csrf "$BASE/hostshield/")"
check "installer page has a form" test -n "$TOKEN"
curl -s -o /dev/null -b "$JAR" -c "$JAR" "$BASE/hostshield/" \
    --data-urlencode "csrf=$TOKEN" --data-urlencode "data_dir=/var/www/hostshield-data" \
    --data-urlencode "user=admin" --data-urlencode "email=admin@example.com" \
    --data-urlencode "password=e2e-shield-password" --data-urlencode "password2=e2e-shield-password" \
    --data-urlencode "language=en" --data-urlencode "timezone=Europe/Sofia" --data-urlencode "paths[]=/var/www/html"
check "config.php written" web 'test -f /var/www/hostshield/config.php'
check "settings.php written" web 'test -f /var/www/hostshield-data/settings.php'
check "logged in after install" bash -c "curl -s -b '$JAR' '$BASE/hostshield/' | grep -q 'Setup checklist'"
check "site discovered" bash -c "curl -s -b '$JAR' '$BASE/hostshield/' | grep -q 'WordPress'"

# The docker wp-config reads credentials from the environment, so set them like a user would in site settings.
shield_php 'require "lib/core.php"; $s = shield_settings(); $k = array_key_first($s["sites"]); $s["sites"][$k]["url"] = "http://127.0.0.1:8090"; $s["sites"][$k]["hosts"] = ["127.0.0.1", "localhost"]; $s["sites"][$k]["db"] = ["host" => "db", "port" => 3306, "user" => "wp", "pass" => "wp-password"]; $s["sites"][$k]["databases"] = ["wp"]; shield_settings_save($s); echo $k;' > /tmp/hs-site
SITE="$(cat /tmp/hs-site)"
check "site key is html" test "$SITE" = "html"

echo "== First cron run (baseline, uptime, audit)"
www 'php /var/www/hostshield/cron/worker.php' >/dev/null 2>&1
check "integrity baseline" web 'test -f /var/www/hostshield-data/integrity/html.baseline.json'
check "uptime recorded" bash -c "dc exec -T web cat /var/www/hostshield-data/uptime/html.json | grep -q '\"code\": 200'"
check "audit stored" web 'test -f /var/www/hostshield-data/audit/html.json'

echo "== Firewall"
TOKEN="$(csrf "$BASE/hostshield/?p=site&site=html")"
curl -s -o /dev/null -b "$JAR" -c "$JAR" "$BASE/hostshield/" --data "csrf=$TOKEN&action=waf_on&site=html"
check "firewall line added to .htaccess (mod_php)" web 'grep -q "php_value auto_prepend_file" /var/www/html/.htaccess'
check "site still works with the firewall" test "$(code "$BASE/")" = "200"
check "heartbeat seen" web 'test -f /var/www/hostshield-data/waf/heartbeat/html'
code "$BASE/?author=1" >/dev/null
check "log mode: user enumeration logged, not blocked" bash -c "dc exec -T web sh -c 'cat /var/www/hostshield-data/logs/waf-*.jsonl' | grep -q wp_user_enum"
shield_php 'require "lib/core.php"; $s = shield_settings(); $s["waf"]["mode"] = "block"; shield_settings_save($s);'
check "block mode: user enumeration blocked" test "$(code "$BASE/?author=1")" = "403"
web 'mkdir -p /var/www/html/wp-content/uploads/2026 && printf "<?php echo \"ran\";\n" > /var/www/html/wp-content/uploads/2026/e2e-check.php && chown -R www-data /var/www/html/wp-content/uploads'
check "PHP in uploads cannot run" test "$(code "$BASE/wp-content/uploads/2026/e2e-check.php")" = "403"
check "homepage still 200 in block mode" test "$(code "$BASE/")" = "200"
check "wp-login still reachable" test "$(code "$BASE/wp-login.php")" = "200"
shield_php 'require "lib/core.php"; $s = shield_settings(); $s["waf"]["mode"] = "log"; shield_settings_save($s); foreach (glob(shield_path("waf/bans/*.json")) as $f) unlink($f);'

echo "== Scanner and quarantine"
www 'php /var/www/hostshield/cron/worker.php --scan html' > /tmp/hs-scan 2>&1
check "PHP in uploads flagged" grep -q 'e2e-check.php \[code_in_uploads\]' /tmp/hs-scan
shield_php 'require "lib/core.php"; require "lib/scanner.php"; shield_quarantine_file("html", "wp-content/uploads/2026/e2e-check.php", ["code_in_uploads"]);'
check "quarantine removed the file" web '! test -f /var/www/html/wp-content/uploads/2026/e2e-check.php'
check "file kept in quarantine" web 'ls /var/www/hostshield-data/quarantine/html/*/file.bin'

echo "== Backup"
www 'php /var/www/hostshield/cron/worker.php --backup html' > /tmp/hs-backup 2>&1
BK="$(web 'ls /var/www/hostshield-data/backups/html | grep manual | tail -1' | tr -d '\r')"
check "backup created" test -n "$BK"
check "files.zip present" web "test -s /var/www/hostshield-data/backups/html/$BK/files.zip"
check "database dump present" web "test -s /var/www/hostshield-data/backups/html/$BK/db-wp.sql.gz"
check "dump is complete" web "zcat /var/www/hostshield-data/backups/html/$BK/db-wp.sql.gz | grep -q 'HostShield dump complete'"

echo "== Simulated hack, then restore"
dc exec -T db mariadb -uwp -pwp-password wp -e "UPDATE wp_options SET option_value='HACKED' WHERE option_name='blogname'"
web 'printf "<?php // dropped by the test\n" > /var/www/html/e2e-dropped.php && chown www-data /var/www/html/e2e-dropped.php'
www "php /var/www/hostshield/cron/worker.php --restore html $BK all" > /tmp/hs-restore 2>&1
check "restore finished" grep -q 'Done.' /tmp/hs-restore
check "database content restored" bash -c "dc exec -T db mariadb -N -uwp -pwp-password wp -e \"SELECT option_value FROM wp_options WHERE option_name='blogname'\" | grep -q 'HostShield E2E'"
check "dropped file removed" web '! test -f /var/www/html/e2e-dropped.php'
check "safety backup taken" web 'ls /var/www/hostshield-data/backups/html | grep -q pre-restore'
check "site works after restore" test "$(code "$BASE/")" = "200"

echo "== Off-site storage (MinIO)"
shield_php 'require "lib/core.php"; require "lib/offsite.php";
  $s = shield_settings();
  $s["backup"]["offsite"] = ["type" => "s3", "s3" => ["endpoint" => "http://minio:9000", "region" => "us-east-1", "bucket" => "shield", "key" => "hostshield", "secret" => "hostshield-secret", "prefix" => "e2e/", "path_style" => true], "ftp" => $s["backup"]["offsite"]["ftp"]];
  shield_settings_save($s);
  $r = shield_s3_request("PUT", "", []); echo "bucket:" . $r["code"], "\n";
  echo shield_offsite_test(shield_config()["backup"]["offsite"]), "\n";' > /tmp/hs-s3 2>&1
check "S3 connection test" grep -q 'S3 connection works' /tmp/hs-s3
www 'php /var/www/hostshield/cron/worker.php --backup html' > /tmp/hs-backup2 2>&1
check "backup copied off-site" bash -c "! grep -q 'OFF-SITE FAILED' /tmp/hs-backup2"
shield_php 'require "lib/core.php"; require "lib/backup.php"; echo count(shield_offsite_list("html"));' > /tmp/hs-remote
check "remote backup listed" bash -c "test \"\$(cat /tmp/hs-remote)\" -ge 1"
REMOTE="$(shield_php 'require "lib/core.php"; require "lib/backup.php"; echo array_key_first(shield_offsite_list("html"));' | tr -d '\r')"
web "rm -rf /var/www/hostshield-data/backups/html/$REMOTE"
shield_php "require \"lib/core.php\"; require \"lib/backup.php\"; shield_offsite_fetch(\"html\", \"$REMOTE\");"
check "backup downloaded back from S3 and verified" web "test -s /var/www/hostshield-data/backups/html/$REMOTE/files.zip"

echo "== Audit"
www 'php /var/www/hostshield/cron/worker.php --audit html' > /tmp/hs-audit 2>&1
check "audit graded the site" grep -q 'grade [A-F]' /tmp/hs-audit
sed -n '1,40p' /tmp/hs-audit

echo "== Dashboard pages render"
for p in home firewall jobs settings about "site&site=html" "site&site=html&tab=backups" "site&site=html&tab=files" "site&site=html&tab=audit" "site&site=html&tab=settings" site_add; do
    check "page $p" bash -c "curl -s -b '$JAR' '$BASE/hostshield/?p=$p' | grep -q '</html>'"
done
check "no PHP errors in Apache log" bash -c "! dc logs web 2>&1 | grep -E 'PHP (Fatal|Warning|Parse)'"

echo
echo "E2E: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
