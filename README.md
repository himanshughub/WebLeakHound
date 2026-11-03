# WebLeakHound
WebLeakHound is a PowerShell attack-surface scanner. From a root domain (e.g. example.com) it enumerates active-cert subdomains via crt.sh and probes each for leaked files (.env, .git, dumps, backups, creds), secrets in page/JS source (API keys, tokens, JWTs), PII, open Firebase DBs, insecure session cookies, and defacement notes left by hackers.
