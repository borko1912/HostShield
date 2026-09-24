# Security policy

HostShield protects other people's sites, so vulnerabilities in it matter. Thank you for reporting them responsibly.

## Reporting

**Do not open a public issue.** Use GitHub's private reporting instead:
*Security → Report a vulnerability* on https://github.com/borko1912/HostShield.

Please include the version, how to reproduce it, and the impact. You will get an answer within 7 days.
Fixes are released as soon as possible, and reporters are credited in the changelog unless they prefer not to be.

## Scope

In scope: the dashboard (authentication, CSRF, access to backups and settings), the firewall (bypasses that let a
request through that a rule is meant to stop, or crashes that break the protected site), the worker (restore, archive
handling), and the installer.

Out of scope: attacks that need an already compromised hosting account, missing features (for example country blocking),
and false positives (please open a normal issue for those).

## Supported versions

Only the latest release receives security fixes.
