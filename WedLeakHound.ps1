<#
.SYNOPSIS
    Find-WebDataLeak - Subdomain enumeration + exposed-data / secret / PII discovery for a root domain.

.DESCRIPTION
    Give it a single root domain (e.g. example.com). Like PHPFinder, it pulls every
    subdomain from crt.sh certificate-transparency logs, then for each live host it:

      1. Probes for commonly-leaked FILES (.env, .git/config, SQL dumps, backups,
         cloud creds, .htpasswd, web.config, open directory listings, Firebase
         init.json, etc.) and confirms each with a content signature so soft-404
         pages that return 200 for everything are not reported.

      2. Inspects PAGE SOURCE + linked JavaScript bundles for leaked SECRETS -
         Google/Firebase API keys, AWS keys, Stripe/Slack/GitHub/SendGrid tokens,
         private keys, JWTs, and generic api_key / client_secret assignments
         (the kind of thing visible in "inspect element").

      3. Scans exposed content for PII - SSN values and fields such as first_name,
         last_name, ssn, street_address, postal_code, phone, contact_person,
         telephone, date_of_birth. PII in an exposed data file / API response is
         scored higher than the same field names in an ordinary HTML form.

      4. Finds Firebase projects (from page source or /__/firebase/init.json),
         derives the Realtime Database URL (incl. the "<proj>-default-rtdb" form),
         and ACTIVELY tests "<db>/.json" to see if the database is world-readable.

      5. Flags DEFACEMENT indicators - hacker notes left after a site is defaced
         ("hacked by", "defaced", "pwned", crew tags, greetz, etc.) - scanned in BOTH
         the page content and the response metadata (Set-Cookie, X-Powered-By, Server,
         X-Hacker ...). Scored Medium [REVIEW] so you can confirm a possible compromise.

      6. Analyses COOKIES (Set-Cookie headers): session/auth cookies missing HttpOnly,
         Secure or SameSite (stealable via XSS/MITM -> High), and tokens/JWTs sitting in
         a cookie value. Benign (analytics) and CSRF cookies are not flagged.

    Every secret value, PII value, SQL row and DB sample is REDACTED in the report:
    findings prove a leak exists and show a masked locator, never the live data.

    Intended for attack-surface assessment of assets you own or are authorized to
    test. You are responsible for staying in scope.

.PARAMETER Domain
    Root domain to assess, e.g. example.com. In-scope subdomains come from crt.sh.

.PARAMETER OutDir           Directory for the CSV report. Default: current dir.
.PARAMETER ThrottleLimit    Max concurrent host probes (PS7+). Default 20.
.PARAMETER TimeoutSec       Per-request timeout (headers + body). Default 10.
.PARAMETER LoadTimeoutSec   If a host's root page doesn't load within this, the host is skipped. Default 15.
.PARAMETER ConnectTimeoutSec Fast TCP-connect pre-check timeout; a host with no open web port is skipped this quickly. Default 7.
.PARAMETER MaxHostSeconds   Hard time budget per host; probing stops once exceeded. Default 180.
.PARAMETER MaxJsPerHost     Max same-host JS files to fetch & scan per host. Default 12.
.PARAMETER MaxLinksPerHost  Max discovered links (robots/sitemap/anchors) to fetch per host. Default 30.
.PARAMETER Paths            File of URL paths (one per line) probed + scanned on EVERY host - a brute-force wordlist for blind/unlinked endpoints. '#' lines ignored.
.PARAMETER UrlList          File of absolute URLs (gau/waybackurls export) fetched + scanned directly; their hosts are added to scope.
.PARAMETER Subdomains       Optional extra hosts to add to the crt.sh results.
.PARAMETER NoCrtSh          Skip crt.sh and scan only -Subdomains.
.PARAMETER NoContentScan    Skip page/JS secret + PII inspection (files only).
.PARAMETER NoFirebaseCheck  Skip the active Firebase /.json read test.
.PARAMETER NoDiscovery      Skip robots.txt / sitemap.xml / link discovery.
.PARAMETER IncludeWildcards (Deprecated) Wildcard CT entries are now always collapsed to their base name and included, matching PHPFinder.
.PARAMETER IncludeExpired   Drop crt.sh's &exclude=expired filter and include hosts from expired certs too. By default only active (non-expired) certs are used, exactly like PHPFinder.
.PARAMETER ShowValues       Show the ACTUAL matched secret/PII values instead of masking them, for true/false-positive triage. WARNING: the report then contains live secrets/PII in cleartext - handle it securely. Off by default.
.PARAMETER Excel            Write the colour-highlighted .xlsx report (needs ImportExcel; falls back to HTML).
.PARAMETER Html             Write the interactive colour-coded .html report (Reveal buttons for values).
.PARAMETER Csv              Also write a plain .csv (no colour). Always opt-in.
                            With no report switch, BOTH .xlsx and .html are written by default.

.EXAMPLE
    .\Find-WebDataLeak.ps1 -Domain example.com

.EXAMPLE
    .\Find-WebDataLeak.ps1 -Domain example.com -ThrottleLimit 40 -OutDir C:\Reports

.NOTES
    PowerShell 7+ recommended (uses -Parallel). Falls back to sequential on 5.1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidatePattern('^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$')]
    [string]$Domain,

    [string]$OutDir = ".",
    [ValidateRange(1, 200)][int]$ThrottleLimit = 20,
    [ValidateRange(1, 120)][int]$TimeoutSec = 10,
    [ValidateRange(1, 120)][int]$LoadTimeoutSec = 15,
    [ValidateRange(1, 60)][int]$ConnectTimeoutSec = 7,
    [ValidateRange(10, 3600)][int]$MaxHostSeconds = 180,
    [ValidateRange(0, 100)][int]$MaxJsPerHost = 12,
    [ValidateRange(0, 200)][int]$MaxLinksPerHost = 30,
    [string]$Paths,
    [string]$UrlList,
    [string[]]$Subdomains,
    [switch]$NoCrtSh,
    [switch]$NoContentScan,
    [switch]$NoFirebaseCheck,
    [switch]$NoDiscovery,
    [switch]$IncludeWildcards,
    [switch]$IncludeExpired,
    [switch]$ShowValues,
    [switch]$Excel,
    [switch]$Html,
    [switch]$Csv
)

$ErrorActionPreference = 'Stop'
$Domain = $Domain.Trim().ToLowerInvariant().TrimEnd('.')

# Windows PowerShell 5.1 does not auto-load System.Net.Http; load it so HttpClient works.
try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {}

# Windows PowerShell 5.1 defaults to TLS 1.0; make sure modern TLS is available.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 } catch {}

# ---------------------------------------------------------------------------
# Exposed-FILE probes: path -> signature that proves it is the real file.
# ---------------------------------------------------------------------------
$Script:FilePaths = @(
    [pscustomobject]@{ Path = '/.env';                  Sev = 'Critical'; Data = $true;  Regex = '(?im)^\s*(APP_KEY|DB_(PASSWORD|USERNAME|HOST|DATABASE)|SECRET|.*_SECRET|.*_KEY|AWS_(ACCESS|SECRET)|STRIPE_|MAIL_PASSWORD|FIREBASE)\s*=\s*\S' }
    [pscustomobject]@{ Path = '/.git/config';           Sev = 'High';     Data = $false; Regex = '(?im)\[core\]|repositoryformatversion|\[remote ' }
    [pscustomobject]@{ Path = '/.git/HEAD';             Sev = 'High';     Data = $false; Regex = '(?im)^ref:\s+refs/' }
    [pscustomobject]@{ Path = '/.svn/entries';          Sev = 'High';     Data = $false; Regex = '(?im)svn://|dir\b|^\d+\s*$' }
    [pscustomobject]@{ Path = '/.DS_Store';             Sev = 'Low';      Data = $false; Regex = 'Bud1' }
    [pscustomobject]@{ Path = '/.htpasswd';             Sev = 'High';     Data = $true;  Regex = '(?m)^[A-Za-z0-9_.-]+:\$(apr1|2y|1|6)\$' }
    [pscustomobject]@{ Path = '/wp-config.php.bak';     Sev = 'Critical'; Data = $true;  Regex = '(?im)DB_PASSWORD|DB_NAME|AUTH_KEY' }
    [pscustomobject]@{ Path = '/config.php.bak';        Sev = 'Critical'; Data = $true;  Regex = '(?im)password|passwd|db_|mysql' }
    [pscustomobject]@{ Path = '/config.php~';           Sev = 'Critical'; Data = $true;  Regex = '(?im)password|passwd|db_|mysql' }
    [pscustomobject]@{ Path = '/.aws/credentials';      Sev = 'Critical'; Data = $true;  Regex = '(?im)aws_access_key_id|aws_secret_access_key|AKIA[0-9A-Z]{16}' }
    [pscustomobject]@{ Path = '/credentials.json';      Sev = 'Critical'; Data = $true;  Regex = '(?im)private_key|client_secret|AKIA[0-9A-Z]{16}|"type"\s*:\s*"service_account"' }
    [pscustomobject]@{ Path = '/.npmrc';                Sev = 'High';     Data = $true;  Regex = '(?im)_authToken=|_auth=|//.*:_password' }
    [pscustomobject]@{ Path = '/appsettings.json';      Sev = 'High';     Data = $true;  Regex = '(?im)ConnectionStrings|"Password"\s*:|AccountKey=' }
    [pscustomobject]@{ Path = '/web.config';            Sev = 'High';     Data = $true;  Regex = '(?im)<connectionStrings|password=' }
    [pscustomobject]@{ Path = '/backup.sql';            Sev = 'Critical'; Data = $true;  Regex = '(?im)INSERT INTO|CREATE TABLE|-- (MySQL|MariaDB|PostgreSQL) dump|DROP TABLE' }
    [pscustomobject]@{ Path = '/database.sql';          Sev = 'Critical'; Data = $true;  Regex = '(?im)INSERT INTO|CREATE TABLE|-- (MySQL|MariaDB|PostgreSQL) dump|DROP TABLE' }
    [pscustomobject]@{ Path = '/dump.sql';              Sev = 'Critical'; Data = $true;  Regex = '(?im)INSERT INTO|CREATE TABLE|-- (MySQL|MariaDB|PostgreSQL) dump|DROP TABLE' }
    [pscustomobject]@{ Path = '/db.sql';                Sev = 'Critical'; Data = $true;  Regex = '(?im)INSERT INTO|CREATE TABLE|DROP TABLE' }
    [pscustomobject]@{ Path = '/backup.zip';            Sev = 'High';     Data = $false; Type  = 'binzip' }
    [pscustomobject]@{ Path = '/backup.tar.gz';         Sev = 'High';     Data = $false; Type  = 'bingz' }
    [pscustomobject]@{ Path = '/phpinfo.php';           Sev = 'Medium';   Data = $false; Regex = '(?im)<title>phpinfo\(\)|PHP Version\s*</td>|\bphpinfo\(\)' }
    [pscustomobject]@{ Path = '/server-status';         Sev = 'Medium';   Data = $false; Regex = '(?im)Apache Server Status|Server uptime|Scoreboard' }
    [pscustomobject]@{ Path = '/.vscode/sftp.json';     Sev = 'High';     Data = $true;  Regex = '(?im)"password"|"privateKeyPath"|"host"' }
    [pscustomobject]@{ Path = '/__/firebase/init.json'; Sev = 'Medium';   Data = $true;  Regex = '(?im)"(apiKey|databaseURL|projectId|storageBucket)"\s*:' }
    [pscustomobject]@{ Path = '/';                      Sev = 'Low';      Data = $false; Regex = '(?im)<title>Index of /|\[To Parent Directory\]|Directory listing for' }
)

# ---------------------------------------------------------------------------
# SECRET patterns - scanned in page HTML, inline <script>, and JS bundles.
# High specificity to keep noise low.
# ---------------------------------------------------------------------------
$Script:SecretPatterns = @(
    [pscustomobject]@{ Name = 'Google/Firebase API key';      Sev = 'High';     Rx = 'AIza[0-9A-Za-z_\-]{35}' }
    [pscustomobject]@{ Name = 'AWS access key id';            Sev = 'Critical'; Rx = '\bAKIA[0-9A-Z]{16}\b' }
    [pscustomobject]@{ Name = 'AWS secret access key';        Sev = 'Critical'; Rx = '(?i)aws_secret_access_key["'' :=]{1,4}["'']?[0-9A-Za-z/+]{40}' }
    [pscustomobject]@{ Name = 'GCP service-account key';      Sev = 'Critical'; Rx = '"type"\s*:\s*"service_account"' }
    [pscustomobject]@{ Name = 'Private key block';            Sev = 'Critical'; Rx = '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----' }
    [pscustomobject]@{ Name = 'Slack token';                  Sev = 'Critical'; Rx = 'xox[baprs]-[0-9A-Za-z-]{10,}' }
    [pscustomobject]@{ Name = 'Slack webhook';                Sev = 'High';     Rx = 'https://hooks\.slack\.com/services/[A-Za-z0-9/]+' }
    [pscustomobject]@{ Name = 'Stripe live secret key';       Sev = 'Critical'; Rx = 'sk_live_[0-9a-zA-Z]{20,}' }
    [pscustomobject]@{ Name = 'Stripe live publishable key';  Sev = 'Low';      Rx = 'pk_live_[0-9a-zA-Z]{20,}' }
    [pscustomobject]@{ Name = 'GitHub token';                 Sev = 'Critical'; Rx = 'gh[pousr]_[0-9A-Za-z]{36,}' }
    [pscustomobject]@{ Name = 'Google OAuth client secret';   Sev = 'High';     Rx = 'GOCSPX-[0-9A-Za-z_\-]{20,}' }
    [pscustomobject]@{ Name = 'SendGrid API key';             Sev = 'Critical'; Rx = 'SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}' }
    [pscustomobject]@{ Name = 'Twilio account SID';           Sev = 'High';     Rx = '\bAC[0-9a-fA-F]{32}\b' }
    [pscustomobject]@{ Name = 'Mailgun key';                  Sev = 'High';     Rx = '\bkey-[0-9a-f]{32}\b' }
    [pscustomobject]@{ Name = 'Firebase Cloud Messaging key'; Sev = 'High';     Rx = 'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{100,}' }
    [pscustomobject]@{ Name = 'JWT';                          Sev = 'Medium';   Rx = 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}' }
    [pscustomobject]@{ Name = 'Generic secret assignment';    Sev = 'Medium';   Rx = '(?i)(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|secret[_-]?key|auth[_-]?token|private[_-]?key)["'' :=]{1,4}["'']?[0-9A-Za-z_\-]{16,}' }
)

# ---------------------------------------------------------------------------
# PII patterns. 'FieldSev' = severity when the hit is in an exposed data file /
# API response; in ordinary HTML it is downgraded (likely just a form).
# ---------------------------------------------------------------------------
$Script:PiiPatterns = @(
    [pscustomobject]@{ Name = 'US SSN value';     Sev = 'Critical'; Web = 'High';   Rx = '\b\d{3}-\d{2}-\d{4}\b';  Value = $true }
    [pscustomobject]@{ Name = 'Credit-card-like'; Sev = 'High';     Web = 'Medium'; Rx = '\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b'; Value = $true }
    [pscustomobject]@{ Name = 'Email address';    Sev = 'High';     Web = 'Low';    Rx = '[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}'; Value = $true }
    [pscustomobject]@{ Name = 'Phone number';     Sev = 'High';     Web = 'Low';    Rx = '(?<![\d\-])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?![\d\-])'; Value = $true }
    [pscustomobject]@{ Name = 'PII fields';       Sev = 'High';     Web = 'Low';    Value = $false;
        Rx = '(?i)\b(first[_ ]?name|last[_ ]?name|full[_ ]?name|ssn|social[_ ]?security|street[_ ]?address|\baddress\b|postal[_ ]?code|zip[_ ]?code|contact[_ ]?person|tele(?:phone)?|\bphone\b|date[_ ]?of[_ ]?birth|\bdob\b)\b' }
)

# DEFACEMENT indicators - hacker notes left after defacing a site. Scanned in page
# content AND response metadata (Set-Cookie, X-Powered-By, Server, X-Hacker, etc.).
# Flagged Medium -> [REVIEW]: confirm whether a compromise / left-behind note occurred.
$Script:DefacePatterns = @(
    '(?i)\bhacked[\s_-]*by\b'
    '(?i)\bdefaced[\s_-]*by\b'
    '(?i)\bpwned[\s_-]*by\b'
    '(?i)\bhackedby\b|\bdefacer\b|\bth3[\s_-]*cr3w\b'
    '(?i)\b(h4ck3d|h4x0r|0wn3d|pwn3d|d3fac3d|h4cked)\b'
    '(?i)\bthis\s+(site|server|website|domain)\s+(has\s+been\s+|was\s+|is\s+)?(hacked|defaced|compromised|owned|pwned)\b'
    '(?i)\byou(r)?\s+(got|have\s+been|been|site\s+is)\s+hacked\b'
    '(?i)\bsecurity\s+is\s+(just\s+)?an?\s+illusion\b'
    '(?i)\byour\s+security\s+is\s+(low|weak|zero|none|poor)\b'
    '(?i)\bgreet(z|ings)\b.{0,40}\b(to|team|crew)\b'
    '(?i)\bcyber[\s_-]*(army|team|caliphate|warriors?|skull|troops?)\b'
    '(?i)\b(mr|mrs|dr|eng)\.?\s*[\w.-]{2,20}\s+was\s+here\b'
    '(?i)\bowned\s+by\s+[\w.\- ]{2,30}\b(team|crew|hacker|group|army)\b'
    '(?i)\b(f[\*u]ck|death\s+to)\s+(israel|usa|india|the\s+(gov|government|system|police))\b'
    '(?i)\bno\s+system\s+is\s+safe\b|\byour\s+system\s+(is|has\s+been)\s+(hacked|breached)\b'
    '(?i)\bstamp(ed)?\s+by\b.{0,30}\b(hacker|crew|team)\b'
    '(?i)\bleet\s+hax?or\b|\bskid[\s_-]*crew\b|\bgov[\s_-]*hacked\b'
)

# Secret / value maskers applied to every evidence snippet before it is stored.
$Script:Maskers = @(
    @{ Rx = '(?im)(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)'; Repl = '$1 [REDACTED] $2' }
    @{ Rx = '(?i)\bAKIA[0-9A-Z]{16}\b'; Repl = 'AKIA[REDACTED]' }
    # High-entropy token formats (so a detected secret is never printed in cleartext in its evidence).
    @{ Rx = 'AIza[0-9A-Za-z_\-]{35}'; Repl = 'AIza[REDACTED]' }
    @{ Rx = '(?i)\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{10,}'; Repl = '$1_$2_[REDACTED]' }
    @{ Rx = '\bgh[pousr]_[0-9A-Za-z]{30,}\b'; Repl = '[REDACTED-GH-TOKEN]' }
    @{ Rx = 'xox[baprs]-[0-9A-Za-z-]{10,}'; Repl = '[REDACTED-SLACK-TOKEN]' }
    @{ Rx = 'GOCSPX-[0-9A-Za-z_\-]{20,}'; Repl = 'GOCSPX-[REDACTED]' }
    @{ Rx = 'SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}'; Repl = 'SG.[REDACTED]' }
    @{ Rx = 'eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{2,}'; Repl = '[REDACTED-JWT]' }
    @{ Rx = '(?im)([\w.-]*(?:passwor?d|pwd|secret|token|api[_-]?key|[_-]key|auth|access[_-]?key|credential|conn(?:ection)?[_-]?string)[\w.-]*\s*[:=]\s*["'']?)([^"''\s,;<]{2,})'; Repl = '$1********' }
    @{ Rx = '(?im)(\bVALUES\b\s*)\((?:[^()]|\([^()]*\))*\)'; Repl = '$1([REDACTED-ROW])' }
    @{ Rx = '(?im)^([\w.@-]+:)(\$[0-9a-z]{1,5}\$\S+|\{SHA\}\S+)'; Repl = '$1[REDACTED-HASH]' }
    @{ Rx = '\b\d{3}-\d{2}-\d{4}\b'; Repl = '[REDACTED-SSN]' }
    @{ Rx = '\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b'; Repl = '[REDACTED-CARD]' }
    @{ Rx = '([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,24})'; Repl = '***@$2' }
    @{ Rx = '(?<![\d\-])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?![\d\-])'; Repl = '[REDACTED-PHONE]' }
    @{ Rx = '(?i)\b[A-Za-z0-9+/]{32,}={0,2}\b'; Repl = '[REDACTED-TOKEN]' }
)

function Get-CrtShSubdomains {
    param([string]$Root, [int]$Timeout)
    # Exactly like PHPFinder: let crt.sh filter expired certs server-side with
    # &exclude=expired (no client-side date parsing). Wildcards are collapsed to
    # their base name and included. -IncludeExpired drops the exclude filter.
    $url = "https://crt.sh/?q=%25.$Root&output=json"
    if (-not $IncludeExpired) { $url += "&exclude=expired" }
    $names = [System.Collections.Generic.HashSet[string]]::new()
    $wild = 0; $rawRows = 0
    for ($try = 1; $try -le 4; $try++) {
        try {
            $certs = @(Invoke-RestMethod -Uri $url -TimeoutSec 180 -UserAgent 'Find-WebDataLeak/3.0' -ErrorAction Stop)
            $rawRows = $certs.Count
            foreach ($c in $certs) {
                foreach ($n in (@("$($c.name_value)" -split "`n") + "$($c.common_name)")) {
                    $name = $n.Trim().ToLowerInvariant().TrimEnd('.')
                    if (-not $name) { continue }
                    if ($name.StartsWith('*.')) { $name = $name.Substring(2); $wild++ }   # wildcard -> base name
                    if ($name -notmatch '^[a-z0-9.-]+$') { continue }
                    if ($name -ne $Root -and -not $name.EndsWith(".$Root")) { continue }
                    [void]$names.Add($name)
                }
            }
            break
        } catch {
            $err = ($_.Exception.Message -split "`n")[0].Trim()
            if ($try -lt 4) { $w = 10 * $try; Write-Warning "crt.sh attempt $try/4 failed: $err - retrying in $w s"; Start-Sleep -Seconds $w }
            else { Write-Warning "crt.sh failed after 4 attempts: $err" }
        }
    }
    $tag = if ($IncludeExpired) { 'all certs' } else { 'active certs only' }
    Write-Host "[*] crt.sh ($tag): $rawRows cert entries -> $($names.Count) unique in-scope host(s) ($wild wildcard entries collapsed)" -ForegroundColor DarkGray
    return $names
}

# Core per-host probe. Self-contained so it runs identically in a -Parallel runspace.
$Script:ProbeHost = {
    param($TargetHost, $FilePaths, $SecretPatterns, $PiiPatterns, $DefacePatterns, $Maskers, $Timeout, $LoadTimeout, $ConnectTimeout, $MaxHostSeconds, $MaxJs, $MaxLinks, $DoContent, $DoFirebase, $DoDiscovery, $ExtraPaths, $ExtraUrlMap)

    try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch {}   # 5.1 / fresh-runspace safety
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 } catch {}
    try { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}   # 5.1 cert-bypass fallback
    $findings = [System.Collections.Generic.List[object]]::new()
    $maxBytes = 1048576   # read up to 1 MB per resource (covers JS bundles)
    $dataExt = '\.(json|xml|csv|tsv|txt|xls|xlsx|geojson|rdf|ya?ml|sql|bak|log|conf|ini)(\?|$)'
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'
    # curl.exe (built into Windows 10+) has a browser-like TLS stack and gets through
    # WAFs that silently drop .NET HttpClient. Used only as a fallback when .NET fails.
    $curlExe = $null
    foreach ($cn in @('curl.exe', 'curl')) { try { $g = Get-Command $cn -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1; if ($g) { $curlExe = $g.Source; break } } catch {} }

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    try { $handler.ServerCertificateCustomValidationCallback = { param($m, $c, $ch, $e) $true } } catch {}
    try { $handler.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate } catch {}
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan   # per-request CancellationToken is the real bound
    # Look like a real browser so WAFs (NASA infra etc.) don't reset the connection.
    $client.DefaultRequestHeaders.Add('User-Agent', $ua)
    $client.DefaultRequestHeaders.Add('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8')
    $client.DefaultRequestHeaders.Add('Accept-Language', 'en-US,en;q=0.9')
    try { $client.DefaultRequestHeaders.Add('Upgrade-Insecure-Requests', '1') } catch {}

    # --- local helpers -----------------------------------------------------
    # Registrable domain (last 2 labels, with a few 2-level TLDs) for scope checks.
    $regDom = {
        param($h)
        $h = ($h -split ':')[0].ToLowerInvariant()
        $l = $h -split '\.'
        if ($l.Count -le 2) { return $h }
        $two = @('co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.in', 'com.br', 'co.za')
        $last2 = ($l[-2..-1] -join '.')
        if ($two -contains $last2) { return ($l[-3..-1] -join '.') }
        return $last2
    }
    $origReg = & $regDom (($TargetHost -split ':')[0])
    # Safe host parse: returns $null for malformed URLs (e.g. "https:////www...") instead of throwing.
    $uriHost = { param($u) $z = $null; if ([System.Uri]::TryCreate($u, [System.UriKind]::Absolute, [ref]$z)) { return $z.Host } else { return $null } }

    # Hard-bounded GET: one CancellationToken covers BOTH the header phase and the
    # body read, and the body is streamed with a byte cap - so a server that stalls
    # mid-transfer is aborted at $tmo instead of hanging the whole host.
    # When $follow is set, 3xx redirects are followed (capped) but ONLY within the
    # same registrable domain - so content/discovery reach the real page, while the
    # exposed-file probes (which call without $follow) stay strict.
    $getHttp = {
        param($url, $tmo, $follow)
        if (-not $tmo -or $tmo -le 0) { $tmo = $Timeout }
        $cts = [System.Threading.CancellationTokenSource]::new()
        $cts.CancelAfter([int]([double]$tmo * 1000))
        $cur = $url; $firstCode = $null; $hops = 0; $maxHops = 5
        $r = $null; $stream = $null
        try {
            while ($true) {
                # No Range header: the bounded stream read below caps the body, and a
                # Range request is a common WAF trigger. ResponseHeadersRead means we
                # still never buffer more than $maxBytes regardless of body size.
                $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $cur)
                $r = $client.SendAsync($req, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cts.Token).GetAwaiter().GetResult()
                $code = [int]$r.StatusCode
                if ($null -eq $firstCode) { $firstCode = $code }
                if ($follow -and $hops -lt $maxHops -and $code -ge 300 -and $code -lt 400 -and $r.Headers.Location) {
                    # Follow redirects wherever they lead (incl. cross-domain, e.g. a nasa.gov
                    # host that 302s to its real home on libguides.com). JS/discovery below are
                    # then scoped to whatever registrable domain we actually landed on.
                    $loc = $r.Headers.Location
                    $next = $null
                    try { $next = if ($loc.IsAbsoluteUri) { $loc.AbsoluteUri } else { (New-Object System.Uri([System.Uri]$cur, $loc)).AbsoluteUri } } catch { $next = $null }
                    if (-not $next) { break }
                    $r.Dispose(); $r = $null; $cur = $next; $hops++; continue
                }
                break
            }
            $ct = ''; if ($r.Content.Headers.ContentType) { $ct = $r.Content.Headers.ContentType.MediaType }
            $stream = $r.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $ms = [System.IO.MemoryStream]::new()
            $buf = New-Object byte[] 65536
            while ($ms.Length -lt $maxBytes) {
                $read = $stream.ReadAsync($buf, 0, $buf.Length, $cts.Token).GetAwaiter().GetResult()
                if ($read -le 0) { break }
                $ms.Write($buf, 0, $read)
            }
            $bytes = $ms.ToArray()
            $hdrs = [System.Text.StringBuilder]::new()
            try { foreach ($kv in $r.Headers) { foreach ($v in $kv.Value) { [void]$hdrs.AppendLine("$($kv.Key): $v") } } } catch {}
            try { foreach ($kv in $r.Content.Headers) { foreach ($v in $kv.Value) { [void]$hdrs.AppendLine("$($kv.Key): $v") } } } catch {}
            return [pscustomobject]@{ Code = [int]$r.StatusCode; FirstCode = $firstCode; FinalUrl = $cur; CType = $ct; Bytes = $bytes; Text = [System.Text.Encoding]::UTF8.GetString($bytes); Headers = $hdrs.ToString() }
        } catch { return $null }
        finally { if ($stream) { $stream.Dispose() }; if ($r) { $r.Dispose() }; $cts.Dispose() }
    }
    # curl.exe fallback for WAFs that drop .NET. Follows redirects (-L) only when asked,
    # and stays in scope by checking the effective host's registrable domain.
    $getCurl = {
        param($url, $tmo, $follow)
        if (-not $curlExe) { return $null }
        $bodyFile = [System.IO.Path]::GetTempFileName()
        $hdrFile = [System.IO.Path]::GetTempFileName()
        try {
            $a = @('-s', '-k', '--compressed', '--connect-timeout', [string][int]$ConnectTimeout, '--max-time', [string][int]$tmo,
                '-A', $ua, '-H', 'Accept-Language: en-US,en;q=0.9', '-D', $hdrFile, '-o', $bodyFile, '-w', '%{http_code}|%{url_effective}|%{content_type}')
            if ($follow) { $a += @('-L', '--max-redirs', '5') }
            $a += $url
            $w = & $curlExe @a 2>$null
            if (-not $w) { return $null }
            $parts = "$w".Trim() -split '\|'
            $code = 0; [void][int]::TryParse($parts[0], [ref]$code)
            if ($code -eq 0) { return $null }
            $finalUrl = if ($parts.Count -gt 1 -and $parts[1]) { $parts[1] } else { $url }
            $ctype = if ($parts.Count -gt 2) { ($parts[2] -split ';')[0].Trim() } else { '' }
            $bytes = [byte[]]::new(0)
            try { $fs = [System.IO.File]::OpenRead($bodyFile); $len = [int][Math]::Min([long]$fs.Length, [long]$maxBytes); $bytes = [byte[]]::new($len); [void]$fs.Read($bytes, 0, $len); $fs.Close() } catch {}
            $hdrs = ''; try { $hdrs = Get-Content $hdrFile -Raw -ErrorAction SilentlyContinue } catch {}
            return [pscustomobject]@{ Code = $code; FirstCode = $code; FinalUrl = $finalUrl; CType = $ctype; Bytes = $bytes; Text = [System.Text.Encoding]::UTF8.GetString($bytes); Headers = $hdrs }
        } catch { return $null } finally { Remove-Item $bodyFile, $hdrFile -ErrorAction SilentlyContinue }
    }
    # GET with escalation: try .NET first; if it fails/times out or the WAF returns a
    # block status, retry with curl.exe (different TLS fingerprint).
    $get = {
        param($url, $tmo, $follow)
        $res = & $getHttp $url $tmo $follow
        $blocked = @(401, 403, 406, 429, 503)
        if (($null -eq $res) -or ($blocked -contains $res.Code)) {
            $cu = & $getCurl $url $tmo $follow
            if ($null -ne $cu -and -not ($blocked -contains $cu.Code)) { return $cu }
            if ($null -eq $res -and $null -ne $cu) { return $cu }
        }
        return $res
    }
    # Evidence is stored RAW (collapse whitespace only). Masking is applied later at
    # report time, so the HTML report can hide real values behind a Reveal button.
    $mask = {
        param($s)
        return (($s -replace '\s+', ' ').Trim())
    }
    # Line-aware snippet: never start mid-line (which could orphan a value from its
    # KEY= prefix and defeat masking); clamp the window so JSON one-liners stay short.
    # Fast TCP connect test with a short timeout - lets a dead/filtered port be
    # abandoned in seconds instead of waiting the full HTTP load timeout.
    $tcpTest = {
        param($h, $p, $tmo)
        $c = [System.Net.Sockets.TcpClient]::new()
        try {
            $iar = $c.BeginConnect($h, $p, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne([int]([double]$tmo * 1000), $false)) { $c.EndConnect($iar); return $true }
            return $false
        } catch { return $false } finally { $c.Close() }
    }
    $snippet = {
        param($text, $idx)
        if ($idx -lt 0) { $idx = 0 }; if ($idx -ge $text.Length) { $idx = $text.Length - 1 }
        $s = $text.LastIndexOf("`n", $idx); $s = if ($s -lt 0) { 0 } else { $s + 1 }
        $e = $text.IndexOf("`n", $idx); if ($e -lt 0) { $e = $text.Length }
        if (($idx - $s) -gt 80) { $s = $idx - 80 }
        if (($e - $idx) -gt 160) { $e = $idx + 160 }
        return $text.Substring($s, $e - $s)
    }

    # Scan a blob of text for secrets + PII + defacement notes. $context = 'data'|'web'.
    # $headers (optional) is scanned too, but only for defacement (cookies/powered-by/etc.).
    $scan = {
        param($text, $url, $context, $headers)
        $out = [System.Collections.Generic.List[object]]::new()
        # Defacement: hacker notes in page content OR response metadata (headers).
        $hay = if ($headers) { "$headers`n$text" } else { $text }
        foreach ($dp in $DefacePatterns) {
            $m = [regex]::Match($hay, $dp)
            if ($m.Success) {
                $out.Add([pscustomobject]@{ Url = $url; Category = 'Defacement indicator'; Severity = 'Medium'; Evidence = ('matched: "' + (& $mask (& $snippet $hay $m.Index)) + '"') })
                break
            }
        }
        foreach ($sp in $SecretPatterns) {
            $m = [regex]::Match($text, $sp.Rx)
            if ($m.Success) {
                $out.Add([pscustomobject]@{ Url = $url; Category = "Secret: $($sp.Name)"; Severity = $sp.Sev; Evidence = (& $mask (& $snippet $text $m.Index)) })
            }
        }
        foreach ($pp in $PiiPatterns) {
            $mm = [regex]::Matches($text, $pp.Rx)
            if ($mm.Count -gt 0) {
                $sev = if ($context -eq 'data') { $pp.Sev } else { $pp.Web }
                if ($pp.Value) {
                    $ev = "$($mm.Count) match(es): " + (($mm | ForEach-Object { $_.Value } | Select-Object -Unique | Select-Object -First 10) -join ', ')
                    $out.Add([pscustomobject]@{ Url = $url; Category = "PII: $($pp.Name)"; Severity = $sev; Evidence = $ev })
                } else {
                    $labels = ($mm | ForEach-Object { $_.Value.ToLower() -replace '\s+', '_' } | Select-Object -Unique) -join ','
                    $out.Add([pscustomobject]@{ Url = $url; Category = "PII: $($pp.Name)"; Severity = $sev; Evidence = "fields: $labels" })
                }
            }
        }
        return $out
    }

    # Analyse Set-Cookie headers for stealable/leaky session cookies.
    $cookieScan = {
        param($headers, $url)
        $out = [System.Collections.Generic.List[object]]::new()
        if (-not $headers) { return $out }
        $seen = @{}
        foreach ($line in ($headers -split "[\r\n]+")) {
            if ($line -notmatch '(?i)^\s*set-cookie\s*:\s*(.+)$') { continue }
            $cookie = $Matches[1].Trim()
            $nv = ($cookie -split ';', 2)[0]
            $name = ($nv -split '=', 2)[0].Trim()
            if (-not $name) { continue }
            $val = if (($nv -split '=', 2).Count -gt 1) { ($nv -split '=', 2)[1].Trim() } else { '' }
            $key = $name.ToLower(); if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
            $httpOnly = $cookie -match '(?i);\s*HttpOnly'
            $secure = $cookie -match '(?i);\s*Secure'
            $sameSite = $cookie -match '(?i);\s*SameSite\s*='
            $isCsrf = $name -match '(?i)csrf|xsrf'
            $isSession = $name -match '(?i)(^|[_.\-])(sess|session|sessionid|sid|phpsessid|jsessionid|auth|jwt|token|login|remember|sso|oauth)([_.\-]|$)'
            if ($isSession -and -not $isCsrf) {
                $missing = @()
                if (-not $httpOnly) { $missing += 'HttpOnly' }
                if (-not $secure) { $missing += 'Secure' }
                if (-not $sameSite) { $missing += 'SameSite' }
                if ($missing.Count -gt 0) {
                    $sev = if ((-not $httpOnly) -or (-not $secure)) { 'High' } else { 'Medium' }
                    $out.Add([pscustomobject]@{ Url = $url; Category = "Cookie weakness: $name"; Severity = $sev; Evidence = "session/auth cookie '$name' missing flag(s): $($missing -join ', ') -> stealable via XSS/MITM" })
                }
            }
            # A JWT or long token sitting in a cookie value is itself a sensitive exposure.
            if ($val -match 'eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.' -or $val -match '^[A-Za-z0-9+/]{40,}={0,2}$') {
                $out.Add([pscustomobject]@{ Url = $url; Category = "Cookie: token value exposed"; Severity = 'Medium'; Evidence = "cookie '$name' = $val" })
            }
        }
        return $out
    }

    # --- liveness gate: DNS -> TCP connect -> HTTP load, each fails fast -----
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $overBudget = { $sw.Elapsed.TotalSeconds -ge $MaxHostSeconds }
    $hp = $TargetHost -split ':'
    $dnsHost = $hp[0]
    $ports = if ($hp.Count -gt 1) { @([int]$hp[1]) } else { @(443, 80) }

    # 1) DNS: a name that doesn't resolve is skipped instantly.
    $resolved = $false
    $isIp = $false; try { [void][System.Net.IPAddress]::Parse($dnsHost); $isIp = $true } catch {}
    if ($isIp) { $resolved = $true }
    else { try { $t = [System.Net.Dns]::GetHostAddressesAsync($dnsHost); if ($t.Wait([int]([double]$ConnectTimeout * 1000))) { $resolved = ($t.Result.Length -gt 0) } } catch { $resolved = $false } }
    if (-not $resolved) { $client.Dispose(); $handler.Dispose(); return [pscustomobject]@{ Host = $TargetHost; Loaded = $false; Reason = 'DNS not resolved'; Code = 0; Elapsed = [int]$sw.Elapsed.TotalSeconds; Findings = $findings } }

    # 2) TCP connect on a short timeout, then 3) HTTP GET on the open port
    #    (root follows redirects within the same registrable domain).
    $scheme = $null; $root = $null
    foreach ($p in $ports) {
        if (& $overBudget) { break }
        if (-not (& $tcpTest $dnsHost $p $ConnectTimeout)) { continue }
        $trySchemes = if ($hp.Count -gt 1) { @('https', 'http') } elseif ($p -eq 443) { @('https') } else { @('http') }
        foreach ($s in $trySchemes) {
            $r = & $get "${s}://${TargetHost}/" $LoadTimeout $true
            if ($null -ne $r) { $scheme = $s; $root = $r; break }
        }
        if ($scheme) { break }
    }
    if (-not $scheme) { $client.Dispose(); $handler.Dispose(); return [pscustomobject]@{ Host = $TargetHost; Loaded = $false; Reason = 'no web response'; Code = 0; Elapsed = [int]$sw.Elapsed.TotalSeconds; Findings = $findings } }
    $base = "${scheme}://${TargetHost}"          # original host - used for the strict exposed-file probes

    # Content base = where the root actually landed after following redirects.
    # Root-page links / JS are resolved against this so a redirected site is scanned for real.
    $cBase = $base; $cScheme = $scheme; $cHost = $TargetHost; $redirectedTo = $null
    try {
        $fu = [System.Uri]$root.FinalUrl
        $cBase = "$($fu.Scheme)://$($fu.Authority)"; $cScheme = $fu.Scheme; $cHost = $fu.Host
        if ($root.FinalUrl -notmatch "^$([regex]::Escape($scheme))://$([regex]::Escape($TargetHost))/?$") { $redirectedTo = $fu.Host }
    } catch {}
    $cReg = & $regDom $cHost

    # --- cookie analysis: Set-Cookie headers on the landing response --------
    foreach ($cf in (& $cookieScan $root.Headers $root.FinalUrl)) {
        $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $cf.Url; Category = $cf.Category; Severity = $cf.Severity; Status = $root.Code; ContentType = $root.CType; Bytes = $root.Bytes.Length; Evidence = $cf.Evidence })
    }

    # --- 1. exposed-file probes --------------------------------------------
    foreach ($sig in $FilePaths) {
        if (& $overBudget) { break }
        $resp = if ($sig.Path -eq '/') { $root } else { & $get "$base$($sig.Path)" }
        if ($null -eq $resp) { continue }
        if ($resp.Code -ne 200 -and $resp.Code -ne 206) { continue }

        $expectsHtml = ($sig.Path -eq '/')
        $looksHtml = ($resp.CType -match 'html') -or ($resp.Text -match '(?i)<!doctype html|<html')
        if (-not $expectsHtml -and $looksHtml -and -not ($sig.Path -match '\.(php|config)')) { continue }

        $hit = $false; $ev = ''
        switch ($sig.Type) {
            'binzip' { if ($resp.Bytes.Length -ge 4 -and $resp.Bytes[0] -eq 0x50 -and $resp.Bytes[1] -eq 0x4B) { $hit = $true; $ev = "ZIP archive, $($resp.Bytes.Length)+ bytes" } }
            'bingz'  { if ($resp.Bytes.Length -ge 2 -and $resp.Bytes[0] -eq 0x1F -and $resp.Bytes[1] -eq 0x8B) { $hit = $true; $ev = "gzip archive, $($resp.Bytes.Length)+ bytes" } }
            default  { $m = [regex]::Match($resp.Text, $sig.Regex); if ($m.Success) { $hit = $true; $ev = (& $mask (& $snippet $resp.Text $m.Index)) } }
        }
        if (-not $hit) { continue }

        $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = "$base$($sig.Path)"; Category = 'Exposed file'; Severity = $sig.Sev; Status = $resp.Code; ContentType = $resp.CType; Bytes = $resp.Bytes.Length; Evidence = $ev })
        # Exposed data files: also scan their body for secrets + PII.
        if ($sig.Data) { foreach ($f in (& $scan $resp.Text "$base$($sig.Path)" 'data' $resp.Headers)) { $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $f.Url; Category = $f.Category; Severity = $f.Severity; Status = $resp.Code; ContentType = $resp.CType; Bytes = $resp.Bytes.Length; Evidence = $f.Evidence }) } }
    }

    # --- 2. content inspection: page source + same-host JS -----------------
    $fbText = [System.Text.StringBuilder]::new()
    if ($DoContent -and $root.Code -eq 200) {
        [void]$fbText.Append($root.Text)
        foreach ($f in (& $scan $root.Text $root.FinalUrl 'web' $root.Headers)) { $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $f.Url; Category = $f.Category; Severity = $f.Severity; Status = 200; ContentType = $root.CType; Bytes = $root.Bytes.Length; Evidence = $f.Evidence }) }

        # Gather in-scope script srcs (relative, or absolute within the same registrable domain).
        # Resolved against the content base (where the root actually landed).
        $srcs = [System.Collections.Generic.List[string]]::new()
        foreach ($m in [regex]::Matches($root.Text, '(?i)<script[^>]+src\s*=\s*["'']?([^"''> ]+)')) {
            $u = $m.Groups[1].Value
            if ($u -match '^https?://') { $hh = & $uriHost $u; if (-not $hh -or (& $regDom $hh) -ne $cReg) { continue } }
            elseif ($u.StartsWith('//')) { $u = "${cScheme}:$u"; $hh = & $uriHost $u; if (-not $hh -or (& $regDom $hh) -ne $cReg) { continue } }
            elseif ($u.StartsWith('/')) { $u = "$cBase$u" }
            else { $u = "$cBase/$u" }
            if ($srcs -notcontains $u) { [void]$srcs.Add($u) }
            if ($srcs.Count -ge $MaxJs) { break }
        }
        foreach ($js in $srcs) {
            if (& $overBudget) { break }
            $jr = & $get $js $Timeout $true
            if ($null -eq $jr -or $jr.Code -ne 200) { continue }
            [void]$fbText.Append("`n$($jr.Text)")
            foreach ($f in (& $scan $jr.Text $js 'web' $jr.Headers)) { $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $f.Url; Category = $f.Category; Severity = $f.Severity; Status = 200; ContentType = $jr.CType; Bytes = $jr.Bytes.Length; Evidence = $f.Evidence }) }
        }
    }

    # --- 2b. discovery: robots.txt, sitemap.xml, and same-host data links --
    # Targets unlinked/metadata exposures (e.g. public dataset metadata holding
    # contact PII) that a fixed path list would never reach.
    if ($DoDiscovery -and $MaxLinks -gt 0) {
        $urls = [System.Collections.Generic.HashSet[string]]::new()

        # robots.txt -> Disallow/Allow/Sitemap paths
        $rb = & $get "$cBase/robots.txt" $Timeout $true
        if ($rb -and $rb.Code -eq 200 -and $rb.Text -match '(?im)^\s*(dis)?allow\s*:') {
            foreach ($m in [regex]::Matches($rb.Text, '(?im)^\s*(?:dis)?allow\s*:\s*(\S+)')) {
                $p = $m.Groups[1].Value; if ($p -and $p -ne '/' -and $p -notmatch '\*') { [void]$urls.Add("$cBase$p") }
            }
            foreach ($m in [regex]::Matches($rb.Text, '(?im)^\s*sitemap\s*:\s*(\S+)')) {
                $sm = & $get $m.Groups[1].Value $Timeout $true
                if ($sm -and $sm.Code -eq 200) { foreach ($l in [regex]::Matches($sm.Text, '(?i)<loc>\s*([^<\s]+)\s*</loc>')) { try { if ((& $regDom ([System.Uri]$l.Groups[1].Value).Host) -eq $cReg) { [void]$urls.Add($l.Groups[1].Value) } } catch {} } }
            }
        }
        # default sitemap.xml
        $sm = & $get "$cBase/sitemap.xml" $Timeout $true
        if ($sm -and $sm.Code -eq 200) { foreach ($l in [regex]::Matches($sm.Text, '(?i)<loc>\s*([^<\s]+)\s*</loc>')) { try { if ((& $regDom ([System.Uri]$l.Groups[1].Value).Host) -eq $cReg) { [void]$urls.Add($l.Groups[1].Value) } } catch {} } }

        # in-scope anchor links pointing at data-ish files (resolved against content base)
        if ($root.Code -eq 200) {
            foreach ($m in [regex]::Matches($root.Text, '(?i)<a[^>]+href\s*=\s*["'']?([^"''> ]+)')) {
                $u = $m.Groups[1].Value
                if ($u -match '^(mailto:|tel:|javascript:|#)') { continue }
                if ($u -match '^https?://') { $hh = & $uriHost $u; if (-not $hh -or (& $regDom $hh) -ne $cReg) { continue } }
                elseif ($u.StartsWith('//')) { $u = "${cScheme}:$u"; $hh = & $uriHost $u; if (-not $hh -or (& $regDom $hh) -ne $cReg) { continue } }
                elseif ($u.StartsWith('/')) { $u = "$cBase$u" } else { $u = "$cBase/$u" }
                if ($u -match $dataExt) { [void]$urls.Add($u) }
            }
        }

        $n = 0
        foreach ($u in $urls) {
            if ($n -ge $MaxLinks -or (& $overBudget)) { break }
            $n++
            $dr = & $get $u $Timeout $true
            if ($null -eq $dr -or ($dr.Code -ne 200 -and $dr.Code -ne 206)) { continue }
            $ctx = if (($u -match $dataExt) -or ($dr.CType -match '(?i)json|xml|csv|plain|excel|spreadsheet')) { 'data' } else { 'web' }
            foreach ($f in (& $scan $dr.Text $u $ctx $dr.Headers)) { $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $f.Url; Category = $f.Category; Severity = $f.Severity; Status = $dr.Code; ContentType = $dr.CType; Bytes = $dr.Bytes.Length; Evidence = $f.Evidence }) }
            [void]$fbText.Append("`n$($dr.Text)")   # feed discovered content into Firebase URL extraction too
        }
    }

    # --- 2c. user-supplied wordlist paths (-Paths) + absolute URLs (-UrlList)
    $userTargets = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $ExtraPaths) { $pp = $p; if (-not $pp.StartsWith('/')) { $pp = "/$pp" }; [void]$userTargets.Add("$base$pp") }
    if ($ExtraUrlMap -and $ExtraUrlMap.ContainsKey($TargetHost)) { foreach ($u in $ExtraUrlMap[$TargetHost]) { [void]$userTargets.Add($u) } }
    foreach ($u in ($userTargets | Select-Object -Unique)) {
        if (& $overBudget) { break }
        $ur = & $get $u
        if ($null -eq $ur -or ($ur.Code -ne 200 -and $ur.Code -ne 206)) { continue }
        # If the body matches a known exposed-file signature, flag it as an exposed file.
        foreach ($sig in $FilePaths) {
            if (-not $sig.Regex) { continue }
            $sm2 = [regex]::Match($ur.Text, $sig.Regex)
            if ($sm2.Success) { $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $u; Category = 'Exposed file (wordlist)'; Severity = $sig.Sev; Status = $ur.Code; ContentType = $ur.CType; Bytes = $ur.Bytes.Length; Evidence = (& $mask (& $snippet $ur.Text $sm2.Index)) }); break }
        }
        $ctx = if (($u -match $dataExt) -or ($ur.CType -match '(?i)json|xml|csv|plain|excel|spreadsheet')) { 'data' } else { 'web' }
        foreach ($f in (& $scan $ur.Text $u $ctx $ur.Headers)) { $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $f.Url; Category = $f.Category; Severity = $f.Severity; Status = $ur.Code; ContentType = $ur.CType; Bytes = $ur.Bytes.Length; Evidence = $f.Evidence }) }
        [void]$fbText.Append("`n$($ur.Text)")
    }

    # --- 3. Firebase: discover DB URL, then actively test /.json -----------
    if ($DoFirebase) {
        $blob = $fbText.ToString()
        $cands = [System.Collections.Generic.HashSet[string]]::new()
        # explicit RTDB hosts (classic, -default-rtdb, and regional firebasedatabase.app)
        foreach ($m in [regex]::Matches($blob, '(?i)https://([a-z0-9-]+(?:-default-rtdb)?(?:\.[a-z0-9-]+)?)\.(firebaseio\.com|firebasedatabase\.app)')) {
            [void]$cands.Add("https://$($m.Groups[1].Value).$($m.Groups[2].Value)")
        }
        # databaseURL: "..."
        foreach ($m in [regex]::Matches($blob, '(?i)databaseURL["'' :=]{1,6}["''](https://[^"'']+)["'']')) {
            [void]$cands.Add(($m.Groups[1].Value -replace '/+$',''))
        }
        # derive from firebaseapp / web.app project ids
        foreach ($m in [regex]::Matches($blob, '(?i)https://([a-z0-9-]+)\.(?:firebaseapp\.com|web\.app)')) {
            $p = $m.Groups[1].Value
            [void]$cands.Add("https://$p-default-rtdb.firebaseio.com")
            [void]$cands.Add("https://$p.firebaseio.com")
        }
        foreach ($m in [regex]::Matches($blob, '(?i)"projectId"\s*:\s*"([a-z0-9-]+)"')) {
            $p = $m.Groups[1].Value
            [void]$cands.Add("https://$p-default-rtdb.firebaseio.com")
            [void]$cands.Add("https://$p.firebaseio.com")
        }
        foreach ($db in $cands) {
            if (& $overBudget) { break }
            $jr = & $get "$db/.json"
            if ($null -eq $jr) { continue }
            $body = $jr.Text.Trim()
            if ($jr.Code -eq 200 -and $body -notmatch '(?i)"error"\s*:\s*"Permission denied"') {
                if ($body -eq 'null' -or $body -eq '') {
                    $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = "$db/.json"; Category = 'Firebase: readable (empty root)'; Severity = 'Medium'; Status = 200; ContentType = $jr.CType; Bytes = $jr.Bytes.Length; Evidence = 'RTDB readable without auth; root is null/empty' })
                } else {
                    $ev = (& $mask $body); if ($ev.Length -gt 200) { $ev = $ev.Substring(0, 200) + '...' }
                    $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = "$db/.json"; Category = 'Firebase: OPEN database'; Severity = 'Critical'; Status = 200; ContentType = $jr.CType; Bytes = $jr.Bytes.Length; Evidence = "World-readable RTDB. Sample: $ev" })
                    # the dump itself may contain PII / secrets
                    foreach ($f in (& $scan $jr.Text "$db/.json" 'data' $jr.Headers)) { $findings.Add([pscustomobject]@{ Host = $TargetHost; Url = $f.Url; Category = $f.Category; Severity = $f.Severity; Status = 200; ContentType = $jr.CType; Bytes = $jr.Bytes.Length; Evidence = $f.Evidence }) }
                }
            }
        }
    }

    $client.Dispose(); $handler.Dispose()
    $reason = if ($redirectedTo) { "HTTP $($root.FirstCode)->$($root.Code) $redirectedTo" } else { "HTTP $($root.Code)" }
    return [pscustomobject]@{ Host = $TargetHost; Loaded = $true; Reason = $reason; Code = $root.Code; Elapsed = [int]$sw.Elapsed.TotalSeconds; Findings = $findings }
}

# ---------------------------------------------------------------------------
# 1. Build the host list
# ---------------------------------------------------------------------------
Write-Host "[*] Target root domain: $Domain" -ForegroundColor Cyan
$hosts = [System.Collections.Generic.HashSet[string]]::new()
[void]$hosts.Add($Domain); [void]$hosts.Add("www.$Domain")
if (-not $NoCrtSh) {
    Write-Host "[*] Querying crt.sh for subdomains..." -ForegroundColor Cyan
    foreach ($h in (Get-CrtShSubdomains -Root $Domain -Timeout $TimeoutSec)) { [void]$hosts.Add($h) }
}
if ($Subdomains) { foreach ($s in $Subdomains) { $h = $s.Trim().ToLowerInvariant().TrimEnd('.'); if ($h) { [void]$hosts.Add($h) } } }

# -Paths wordlist (relative paths probed on every host)
$extraPaths = @()
if ($Paths) {
    if (-not (Test-Path $Paths)) { throw "-Paths file not found: $Paths" }
    $extraPaths = Get-Content -LiteralPath $Paths | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^\s*#' }
    Write-Host "[*] Loaded $($extraPaths.Count) wordlist path(s) from $Paths" -ForegroundColor Cyan
}

# -UrlList absolute URLs (scanned directly; their hosts are added to scope)
$extraUrlMap = @{}
if ($UrlList) {
    if (-not (Test-Path $UrlList)) { throw "-UrlList file not found: $UrlList" }
    foreach ($line in (Get-Content -LiteralPath $UrlList)) {
        $u = $line.Trim(); if (-not $u -or $u -match '^\s*#') { continue }
        if ($u -notmatch '^https?://') { $u = "https://$u" }
        try { $auth = ([Uri]$u).Authority.ToLowerInvariant() } catch { continue }
        if (-not $auth) { continue }
        $th = $auth -replace ':(80|443)$', ''          # TargetHost form (strip only default ports)
        [void]$hosts.Add($th)
        if (-not $extraUrlMap.ContainsKey($th)) { $extraUrlMap[$th] = [System.Collections.Generic.List[string]]::new() }
        $extraUrlMap[$th].Add($u)
    }
    $cnt = ($extraUrlMap.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    Write-Host "[*] Loaded $cnt URL(s) from $UrlList across $($extraUrlMap.Keys.Count) host(s)" -ForegroundColor Cyan
}

$hostList = $hosts | Sort-Object
Write-Host "[*] $($hostList.Count) in-scope host(s) to probe." -ForegroundColor Cyan
if ($hostList.Count -eq 0) { Write-Warning "No hosts to scan."; return }

# ---------------------------------------------------------------------------
# 2. Probe (parallel on PS7, sequential on 5.1)
# ---------------------------------------------------------------------------
$all = [System.Collections.Generic.List[object]]::new()
$fp = $Script:FilePaths; $sx = $Script:SecretPatterns; $px = $Script:PiiPatterns; $mx = $Script:Maskers; $dp = $Script:DefacePatterns
$probe = $Script:ProbeHost
$doC = -not $NoContentScan; $doF = -not $NoFirebaseCheck; $doD = -not $NoDiscovery
$total = $hostList.Count
$progress = [hashtable]::Synchronized(@{ done = 0 })   # shared across parallel runspaces; mutated under a lock

# Per-host status line: a severity-coloured label + a short detail.
$statusOf = {
    param($res)
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    if (-not $res.Loaded) { return [pscustomobject]@{ Label = '[SKIPPED]'; Color = 'DarkGray'; Detail = $res.Reason } }
    # Make the HTTP/redirect part readable.
    $http = if ($res.Reason -match 'HTTP\s+\d+->\d+\s+(\S+)') { "redirect -> $($matches[1]) (HTTP $($res.Code))" } else { $res.Reason }
    $f = @($res.Findings)
    if ($f.Count -eq 0) { return [pscustomobject]@{ Label = '[CLEAN]'; Color = 'Green'; Detail = $http } }
    $top = ($f | Sort-Object { $rank[$_.Severity] } | Select-Object -First 1).Severity
    $label = switch ($top) { 'Critical' { '[CRITICAL LEAK]' } 'High' { '[LEAK FOUND]' } 'Medium' { '[REVIEW]' } default { '[INFO]' } }
    $color = switch ($top) { 'Critical' { 'Red' } 'High' { 'Red' } 'Medium' { 'DarkYellow' } default { 'Gray' } }
    $bd = ($f | Group-Object Severity | Sort-Object { $rank[$_.Name] } | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
    return [pscustomobject]@{ Label = $label; Color = $color; Detail = "$bd  -  $http" }
}

if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "[*] PowerShell $($PSVersionTable.PSVersion) - PARALLEL mode, up to $ThrottleLimit hosts at once." -ForegroundColor Green
} else {
    Write-Host "[!] Windows PowerShell $($PSVersionTable.PSVersion) detected - running SEQUENTIAL (one host at a time)." -ForegroundColor Yellow
    Write-Host "    -ThrottleLimit is ignored here. For parallel probing, launch with 'pwsh' instead of 'powershell':" -ForegroundColor Yellow
    Write-Host "    pwsh -ExecutionPolicy Bypass -File .\Find-WebDataLeak.ps1 -Domain $Domain -Paths .\endpoints.txt -ThrottleLimit $ThrottleLimit" -ForegroundColor Yellow
}
if ($ShowValues) { Write-Host "[!] -ShowValues ON: console + CSV/XLSX show matched values in CLEARTEXT (HTML always keeps them behind Reveal buttons). Store output securely." -ForegroundColor Red }
Write-Host "[*] Scanning $total host(s) - started $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Cyan

if ($PSVersionTable.PSVersion.Major -ge 7) {
    $probeText = $Script:ProbeHost.ToString()   # -Parallel can't take a scriptblock via $using:; rebuild from text
    $statusText = $statusOf.ToString()
    $results = $hostList | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $p = [scriptblock]::Create($using:probeText)
        $res = & $p $_ $using:fp $using:sx $using:px $using:dp $using:mx $using:TimeoutSec $using:LoadTimeoutSec $using:ConnectTimeoutSec $using:MaxHostSeconds $using:MaxJsPerHost $using:MaxLinksPerHost $using:doC $using:doF $using:doD $using:extraPaths $using:extraUrlMap
        $pg = $using:progress
        [System.Threading.Monitor]::Enter($pg.SyncRoot); try { $pg['done']++; $d = $pg['done'] } finally { [System.Threading.Monitor]::Exit($pg.SyncRoot) }
        $st = & ([scriptblock]::Create($using:statusText)) $res
        Write-Host ("[{0}] [{1}/{2}] {3,-42} {4,-16} {5}  ({6}s)" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $d, $using:total, $res.Host, $st.Label, $st.Detail, $res.Elapsed) -ForegroundColor $st.Color
        Write-Progress -Activity "Scanning $using:Domain" -Status "$d / $($using:total) hosts" -PercentComplete ([int](($d / $using:total) * 100))
        foreach ($x in $res.Findings) { $x }
    }
    foreach ($r in $results) { if ($r) { $all.Add($r) } }
} else {
    foreach ($h in $hostList) {
        $res = & $probe $h $fp $sx $px $dp $mx $TimeoutSec $LoadTimeoutSec $ConnectTimeoutSec $MaxHostSeconds $MaxJsPerHost $MaxLinksPerHost $doC $doF $doD $extraPaths $extraUrlMap
        $progress['done']++; $d = $progress['done']
        $st = & $statusOf $res
        Write-Host ("[{0}] [{1}/{2}] {3,-42} {4,-16} {5}  ({6}s)" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $d, $total, $res.Host, $st.Label, $st.Detail, $res.Elapsed) -ForegroundColor $st.Color
        Write-Progress -Activity "Scanning $Domain" -Status "$d / $total hosts : $h" -PercentComplete ([int](($d / $total) * 100))
        foreach ($r in $res.Findings) { if ($r) { $all.Add($r) } }
    }
}
Write-Progress -Activity "Scanning $Domain" -Completed

# ---------------------------------------------------------------------------
# 3. Report
# ---------------------------------------------------------------------------
$order = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
$sorted = $all | Sort-Object @{ E = { $order[$_.Severity] } }, Host, Category
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# Report-time redaction. Findings carry RAW evidence; this masks it for display.
# CSV/XLSX/console show masked unless -ShowValues; the HTML embeds raw behind a Reveal button.
$maskVal = {
    param($s)
    if ($null -eq $s -or $s -eq '') { return '' }
    foreach ($mk in $Script:Maskers) { $s = [regex]::Replace($s, $mk.Rx, $mk.Repl) }
    return $s
}
# Evidence as shown in the flat (non-interactive) reports.
$selected = $sorted | Select-Object Host, Url, Category, Severity, Status, ContentType, Bytes,
    @{ N = 'Evidence'; E = { if ($ShowValues) { $_.Evidence } else { & $maskVal $_.Evidence } } }

# Default output: BOTH the colour-coded .xlsx AND the interactive .html.
# Any explicit switch narrows it to just what was asked for. CSV is always opt-in.
$noneSpecified = -not ($Excel -or $Html -or $Csv)
$wantExcel = $Excel -or $noneSpecified
$wantHtml = $Html -or $noneSpecified
$wantCsv = [bool]$Csv

Write-Host "[*] Scan finished $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

if ($sorted.Count -gt 0) {
    $bySev = $sorted | Group-Object Severity | ForEach-Object { "$($_.Name)=$($_.Count)" }
    Write-Host "`n[!] $($sorted.Count) potential finding(s): $($bySev -join '  ')`n" -ForegroundColor Red
    foreach ($f in $sorted) {
        $c = switch ($f.Severity) { 'Critical' { 'Red' } 'High' { 'Magenta' } 'Medium' { 'Yellow' } default { 'Gray' } }
        Write-Host ("  [{0,-8}] {1,-34} {2}" -f $f.Severity, $f.Category, $f.Url) -ForegroundColor $c
        $evShow = if ($ShowValues) { $f.Evidence } else { & $maskVal $f.Evidence }
        if ($evShow) { Write-Host ("             {0}" -f $evShow) -ForegroundColor DarkGray }
    }

    if ($wantCsv) {
        $csvPath = Join-Path $OutDir "dataleak_${Domain}_$stamp.csv"
        $selected | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`n[*] CSV report: $csvPath" -ForegroundColor Green
    }

    # --- colour-highlighted Excel report (default; needs ImportExcel) ------
    if ($wantExcel) {
        $xlsx = Join-Path $OutDir "dataleak_${Domain}_$stamp.xlsx"
        if (Get-Module -ListAvailable -Name ImportExcel) {
            try {
                Import-Module ImportExcel -ErrorAction Stop
                try { Add-Type -AssemblyName System.Drawing -ErrorAction Stop } catch {}
                $fills = @{ Critical = '#C00000'; High = '#E8A33D'; Medium = '#FFD966'; Low = '#D9D9D9' }
                $pkg = $selected | Export-Excel -Path $xlsx -WorksheetName 'DataLeak' -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -PassThru
                $ws = $pkg.Workbook.Worksheets['DataLeak']
                for ($r = 2; $r -le ($sorted.Count + 1); $r++) {
                    $sev = "$($ws.Cells[$r, 4].Value)"
                    if ($fills.ContainsKey($sev)) {
                        $ws.Cells["A$r:H$r"].Style.Fill.PatternType = 'Solid'
                        $ws.Cells["A$r:H$r"].Style.Fill.BackgroundColor.SetColor([System.Drawing.ColorTranslator]::FromHtml($fills[$sev]))
                        if ($sev -in 'Critical') { $ws.Cells["A$r:H$r"].Style.Font.Color.SetColor([System.Drawing.Color]::White) }
                    }
                }
                Close-ExcelPackage $pkg
                Write-Host "[*] Excel report: $xlsx" -ForegroundColor Green
            } catch {
                Write-Warning "Excel export failed ($($_.Exception.Message)); the HTML report still covers these findings."
                $wantHtml = $true
            }
        } else {
            Write-Warning "ImportExcel module not found (no .xlsx). Install with: Install-Module ImportExcel -Scope CurrentUser"
            Write-Warning "The HTML report (always written) still covers these findings."
            $wantHtml = $true
        }
    }

    # --- optional dependency-free HTML report ------------------------------
    if ($wantHtml) {
        $htmlPath = Join-Path $OutDir "dataleak_${Domain}_$stamp.html"
        $rowColor = @{ Critical = '#f8d7da'; High = '#ffe3cc'; Medium = '#fff3cd'; Low = '#e9ecef' }
        $enc = { param($s) if ($null -eq $s) { '' } else { ($s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;') } }
        $sb = [System.Text.StringBuilder]::new()
        $css = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}
h1{font-size:20px;margin:0 0 6px}
p{margin:4px 0}
.warn{background:#fff3cd;border:1px solid #e0c040;padding:8px 12px;border-radius:6px;margin:8px 0}
button{font:inherit;cursor:pointer}
.btn{background:#1b1b1b;color:#fff;border:none;border-radius:5px;padding:5px 10px;margin:6px 0}
table{border-collapse:collapse;width:100%;font-size:13px;table-layout:fixed}
col.c-sev{width:8%}col.c-cat{width:15%}col.c-host{width:15%}col.c-url{width:27%}col.c-stat{width:5%}col.c-ev{width:30%}
th,td{border:1px solid #ccc;padding:7px 9px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}
tr.hdr th{background:#1b1b1b;color:#fff;position:sticky;top:0;z-index:2}
tr.filter th{background:#eee;position:sticky;top:33px;z-index:1;padding:3px}
tr.filter input,tr.filter select{width:100%;box-sizing:border-box;font:inherit;font-size:12px;padding:2px 4px}
td code{font-size:12px;white-space:pre-wrap;word-break:break-all;display:block}
.sev{font-weight:700;white-space:nowrap}
.reveal{background:#eee;border:1px solid #bbb;border-radius:4px;font-size:11px;padding:1px 7px;margin-bottom:4px}
.val .masked{color:#444}
.val .real{display:none;color:#111;font-weight:600}
.val.shown .masked{display:none}
.val.shown .real{display:block}
</style>
'@
        $js = @'
<script>
function tog(b){var c=b.parentElement;c.classList.toggle('shown');b.textContent=c.classList.contains('shown')?'Hide':'Reveal';}
function togAll(){var any=document.querySelector('.val:not(.shown)');document.querySelectorAll('.val').forEach(function(c){var b=c.querySelector('.reveal');if(!b)return;if(any){c.classList.add('shown');b.textContent='Hide';}else{c.classList.remove('shown');b.textContent='Reveal';}});}
function flt(){var f=[];for(var i=0;i<6;i++){var el=document.getElementById('f'+i);f[i]=el?el.value.toLowerCase():'';}
var rows=document.querySelectorAll('#rows tr');var shown=0;
rows.forEach(function(r){var ok=true;for(var i=0;i<6;i++){if(f[i]){var c=r.cells[i];var t=(c?(c.innerText||c.textContent):'').toLowerCase();if(t.indexOf(f[i])<0){ok=false;break;}}}r.style.display=ok?'':'none';if(ok)shown++;});
var n=document.getElementById('shown');if(n)n.textContent=shown;}
function clrF(){for(var i=0;i<6;i++){var el=document.getElementById('f'+i);if(el)el.value='';}flt();}
</script>
'@
        [void]$sb.Append("<!doctype html><html><head><meta charset='utf-8'><title>Data-leak report - $Domain</title>$css$js</head><body>")
        [void]$sb.Append("<h1>Data-leak report &mdash; $(& $enc $Domain)</h1><p>$($sorted.Count) finding(s) across $($hostList.Count) host(s). Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm').</p>")
        [void]$sb.Append("<div class='warn'><b>Note:</b> matched secret/PII values are hidden by default. Click <b>Reveal</b> next to any evidence to view the real value. This file contains those real values &mdash; store it securely and do not share.</div>")
        [void]$sb.Append("<p>" + (($sorted | Group-Object Severity | ForEach-Object { "<b>$($_.Name)</b>: $($_.Count)" }) -join ' &nbsp; ') + "</p>")
        [void]$sb.Append("<button class='btn' onclick='togAll()'>Reveal / hide all</button> <button class='btn' onclick='clrF()'>Clear filters</button> <span style='font-size:12px;color:#555'>Showing <b id='shown'>$($sorted.Count)</b> of $($sorted.Count)</span>")
        [void]$sb.Append("<table><colgroup><col class='c-sev'><col class='c-cat'><col class='c-host'><col class='c-url'><col class='c-stat'><col class='c-ev'></colgroup><thead>")
        [void]$sb.Append("<tr class='hdr'><th>Severity</th><th>Category</th><th>Host</th><th>URL</th><th>Status</th><th>Evidence</th></tr>")
        # per-column filters: Severity dropdown, text filters for the rest
        $sevOpts = "<option value=''>(all)</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option>"
        [void]$sb.Append("<tr class='filter'><th><select id='f0' onchange='flt()'>$sevOpts</select></th><th><input id='f1' oninput='flt()' placeholder='filter...'></th><th><input id='f2' oninput='flt()' placeholder='filter...'></th><th><input id='f3' oninput='flt()' placeholder='filter...'></th><th><input id='f4' oninput='flt()' placeholder='filter...'></th><th><input id='f5' oninput='flt()' placeholder='filter...'></th></tr></thead><tbody id='rows'>")
        foreach ($f in $sorted) {
            $bg = $rowColor[$f.Severity]; if (-not $bg) { $bg = '#fff' }
            $raw = & $enc $f.Evidence
            $masked = & $enc (& $maskVal $f.Evidence)
            # Only add a Reveal button when masking actually hid something.
            $evCell = if ($f.Evidence -and ($masked -ne $raw)) {
                "<div class='val'><button class='reveal' onclick='tog(this)'>Reveal</button><code class='masked'>$masked</code><code class='real'>$raw</code></div>"
            } else { "<code>$raw</code>" }
            [void]$sb.Append("<tr style='background:$bg'><td class='sev'>$(& $enc $f.Severity)</td><td>$(& $enc $f.Category)</td><td>$(& $enc $f.Host)</td><td><code>$(& $enc $f.Url)</code></td><td>$($f.Status)</td><td>$evCell</td></tr>")
        }
        [void]$sb.Append("</tbody></table></body></html>")
        Set-Content -Path $htmlPath -Value $sb.ToString() -Encoding UTF8
        Write-Host "[*] HTML report: $htmlPath" -ForegroundColor Green
    }
} else {
    Write-Host "`n[*] No findings on $($hostList.Count) host(s)." -ForegroundColor Green
}
