# WebLeakHound

WebLeakHound is a PowerShell attack-surface scanner. From a single root domain (for example example.com) it enumerates every active-certificate subdomain from *crt.sh*, then probes each live domain for exposed data. It hunts for leaked files (.env, .git, SQL dumps, backups, cloud credentials), secrets embedded in page source and JavaScript bundles (API keys, AWS/Stripe/GitHub/Slack tokens, private keys, JWTs), and PII (emails, phone numbers, SSNs, and contact-record fields). It also actively tests Firebase Realtime Databases for public read access, inspects Set-Cookie headers for stealable session cookies missing HttpOnly/Secure/SameSite, and flags website-defacement notes left behind by attackers.

Findings are severity-ranked (Critical / High / Medium / Low) and exported to a colour-coded Excel workbook (.xlsx) and an interactive HTML report. Sensitive values are redacted by default and can be revealed per-row in the HTML report for true/false-positive triage.


# What it detects?

*Exposed files* — .env (and variants), .git/config, .svn, SQL dumps, backup.zip/.tar.gz, .aws/credentials, web.config, appsettings.json, .htpasswd, open directory listings, /__/firebase/init.json, and more.
*Secrets in page source & JS bundles* — Google/Firebase API keys, AWS keys, Stripe sk_live, Slack, GitHub, SendGrid, Twilio, private keys, JWTs, and generic api_key / client_secret assignments.
*PII* — SSNs, credit-card-like numbers, email addresses, phone numbers, and contact-record fields (first/last name, address, postal code, DOB…), scored higher when found in exposed data than on an ordinary page.
*Open Firebase databases* — derives the Realtime Database URL from page source / init.json and actively tests /.json for world-readable data.
*Insecure cookies* — session/auth Set-Cookie headers missing HttpOnly, Secure, or SameSite, and tokens/JWTs exposed in cookie values.
*Defacement indicators* — hacker notes (hacked by, defaced, pwned, crew tags, greetz…) in page content and response metadata (headers/cookies).


# How to Run?

Download the script and run it with PowerShell 7+ (pwsh) for parallel probing:

```bash pwsh -ExecutionPolicy Bypass -File .\WebLeakHound.ps1 -Domain <enter-your-organization-domain-here> -Path .\endpoints.txt -ThrottleLimit 60 -ShowValue```

It will enumerate active-cert subdomains under your organization root domain, probe each host, and write the reports to the current folder. For the Excel report, install the one-time dependency:

# Dependency for excel report:

```bash Install-Module ImportExcel -Scope CurrentUser```

Running with powershell (Windows PowerShell 5.1) still works but runs sequentially — use pwsh to get parallel scanning.

enter_domain_prompt

# Available Arguments:

```-Domain``` <root>	Root domain to assess (required).
```-Paths``` <file>	Wordlist of extra paths to probe on every host (ships with endpoints.txt).
```-UrlList``` <file>	Scan an explicit list of URLs (e.g. a gau/waybackurls export).
```-ThrottleLimit``` <n>	Concurrent hosts (PS7+, default 20).
```-TimeoutSec``` / -LoadTimeoutSec / -ConnectTimeoutSec	Per-request, page-load, and TCP-connect timeouts.
```-ShowValues```	Show matched values in cleartext (CSV/XLSX/console) instead of redacting.
```-Excel``` To export result in Excel only
```-Html``` To export result in HTML only
```-Csv``` To export result in CSV only

*Note:* default it saves result in both ```.xlsx``` and ```.html```

Reports
Excel (.xlsx) — severity colour-coded, with native column filters.
HTML — colour-coded, per-column filters (Severity dropdown + text filters), and a Reveal button on every finding so you can view the real value only when you need it. Values are hidden by default.


# Advantage of using this script?

Fully automated and simple to use, with parallel host probing for speed, a WAF-aware curl fallback and cross-domain redirect following for reliability, certificate-aware discovery (only live, active-cert subdomains), and built-in redaction so reports are safe to handle. It consolidates several checks — file exposure, secrets, PII, open Firebase, cookie hygiene, and defacement — into one pass.

# Snapshots of Script Output

