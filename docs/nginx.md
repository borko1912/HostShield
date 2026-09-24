# Running the dashboard on Nginx

Apache and LiteSpeed read the bundled `.htaccess` files. On Nginx, add this to the server block of the dashboard:

```nginx
location ~ ^/(lib|cron|waf|app|lang|tests|docs|\.git|\.github)(/|$) { deny all; }
location ~ ^/(config\.php|install\.unlock)$ { deny all; }
location ~ \.(md|json|jsonl|log|sql|gz|zip|ini|lock)$ { deny all; }
```

To protect a site on Nginx + PHP-FPM, add the firewall to that site's PHP-FPM pool or `.user.ini`:

```ini
auto_prepend_file = "/home/USER/hostshield/waf/firewall.php"
```

`.user.ini` works when `user_ini.filename` is enabled (the default). The dashboard shows the exact line for your install.
