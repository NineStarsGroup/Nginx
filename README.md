## Domain to IP Mapping and TLS/SSL Certificates (with Nginx on Windows)

### Project-specific: domain, ports, and certificate mapping

The following reflects the actual configuration in `conf\nginx.conf` on this machine.

#### HTTP listener (redirects to HTTPS)
- **Port**: 80 (IPv4/IPv6 per default build)
- **Server names** (redirect target respects requested host):
  - `quickbooks.strangled.net`, `ios.strangled.net`, `firebase.strangled.net`, `google.strangled.net`, `upwork.strangled.net`, `yc.strangled.net`,
    `api.dinklife.com`, `dinklife.com`, `jenkins.dinklife.com`, `production.dinklife.com`, `development.dinklife.com`, `devapi.dinklife.com`
- **ACME http-01**: `/.well-known/acme-challenge/` is served from `html` before redirect.

#### HTTPS servers (SNI-based)

| Server name | External port | Certificate (chain) | Certificate (key) | Backend upstream |
|---|---:|---|---|---|
| `firebase.strangled.net` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-key.pem` | `http://127.0.0.1:3003` |
| `upwork.strangled.net` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-key.pem` | `http://127.0.0.1:4001` |
| `quickbooks.strangled.net` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-key.pem` | `http://127.0.0.1:5269` |
| `yc.strangled.net` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/strangled.net-key.pem` | `http://127.0.0.1:4000` |
| `api.dinklife.com` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/dinklife.com-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/dinklife.com-key.pem` | `http://127.0.0.1:4002` |
| `dinklife.com` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/dinklife.com-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/dinklife.com-key.pem` | `http://127.0.0.1:4003` |
| `jenkins.dinklife.com` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-key.pem` | `http://127.0.0.1:8080` |
| `production.dinklife.com` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-key.pem` | `http://127.0.0.1:4004` |
| `development.dinklife.com` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-key.pem` | `http://127.0.0.1:4005` |
| `devapi.dinklife.com` | 443 | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-chain.pem` | `C:/nginx-1.28.0/nginx-1.28.0/cert/jenkins.dinklife.com-key.pem` | `http://127.0.0.1:4006` |

Notes:
- The certificate paths above are absolute; ensure the corresponding files exist under `cert\` with those names.
- All HTTPS servers use `ssl_ciphers HIGH:!aNULL:!MD5` and enable `ssl_prefer_server_ciphers on;` per current config.
- All backends use HTTP/1.1 with upgrade headers set for WebSocket support.

### What “domain → IP mapping” really means
- **DNS translates names to numbers**: When a user enters `example.com`, their system queries DNS to get an IP address (IPv4 A record or IPv6 AAAA record) to connect to your server.
- **Records involved**:
  - **A**: `example.com → 203.0.113.10` (IPv4)
  - **AAAA**: `example.com → 2001:db8::10` (IPv6)
  - **CNAME**: Alias: `www.example.com → example.com` (must not be used at the root/apex)
  - **ALIAS/ANAME**: Provider-specific record acting like a CNAME at the apex
  - **MX** (mail), **TXT** (verification, SPF/DKIM/DMARC, ACME), **CAA** (which CAs may issue your certs)
- **Apex/root vs subdomain**:
  - Apex (`example.com`) typically uses A/AAAA (or ALIAS/ANAME if supported)
  - Subdomains (`www.example.com`) can use CNAME to point to apex/CDN/load balancer
- **TTL (time to live)**: How long resolvers cache results. Lower TTLs speed changes but increase DNS query load.
- **Propagation**: Changes can take time due to caching and registrar/registry updates.
- **Reverse DNS** (PTR): Maps IP → domain; mostly for mail servers and diagnostics. Configured by the IP owner (hosting provider).

### Mapping multiple domains to one server
- **Name-based virtual hosting with SNI**: Multiple domains can share one IP. The client indicates the requested hostname (SNI) during TLS, allowing Nginx to serve the correct certificate.
- **When a dedicated IP may be needed**:
  - Legacy clients without SNI (rare today)
  - Special compliance or reputation reasons
  - Some CDN/WAF setups (less common now)

### Quick DNS verification commands
- Windows PowerShell (preferred):
```powershell
Resolve-DnsName example.com -Type A
Resolve-DnsName example.com -Type AAAA
Resolve-DnsName www.example.com -Type CNAME
Resolve-DnsName example.com -Type TXT
Resolve-DnsName example.com -Type CAA
```
- Classic tools (if installed):
```bash
nslookup example.com
nslookup -type=AAAA example.com
nslookup -type=CNAME www.example.com
```
- Query authoritative nameservers directly (replace with your NS):
```powershell
Resolve-DnsName example.com -Type A -Server ns1.yourdnsprovider.com
```

### Practical DNS mapping scenarios
- **Single site on a VPS**
  - `A` at `example.com` → your VPS IPv4, `AAAA` to IPv6 (if enabled)
  - `CNAME` `www` → `example.com`
- **CDN/WAF in front (e.g., Cloudflare)**
  - `example.com` and `www` → “proxied” CNAME/A as provider instructs
  - Ensure your origin certificate and Nginx still serve valid TLS for origin hostname
  - For ACME http-01, you may need to either pause proxy (grey cloud) or use DNS-01
- **Load balancer**
  - Apex: ALIAS/ANAME → LB hostname if provider supports; otherwise A/AAAA directly
  - Health checks and TLS termination may live on the LB; ensure cert covers client-facing names
- **Internal/testing mapping**
  - Temporary mapping via hosts file (admin editor): `C:\Windows\System32\drivers\etc\hosts`
  - Add: `203.0.113.10  example.com  www.example.com` to override DNS on your machine

### CAA and TXT examples
- **CAA** (only Let’s Encrypt may issue):
```text
example.com. 3600 IN CAA 0 issue "letsencrypt.org"
example.com. 3600 IN CAA 0 issuewild "letsencrypt.org"
example.com. 3600 IN CAA 0 iodef "mailto:admin@example.com"
```
- **ACME DNS-01 TXT** (value auto-generated by client):
```text
_acme-challenge.example.com. 60 IN TXT "<acme-token>"
```

## TLS/SSL Certificates: concepts and choices
- **Certificate types**:
  - **Single-name**: One FQDN, e.g., `www.example.com`
  - **SAN (multi-domain/UCC)**: Many FQDNs in one cert
  - **Wildcard**: `*.example.com` (covers one level, not apex). Often paired with `example.com` as SAN
- **Validation levels**:
  - **DV**: Domain validation (common, fast, automated via ACME)
  - **OV/EV**: Organization/Extended validation (paperwork, rarely needed for APIs/most sites)
- **ACME automation (Let’s Encrypt, ZeroSSL)**:
  - **http-01**: Proves domain via `http://YOUR_DOMAIN/.well-known/acme-challenge/...`
  - **dns-01**: Proves domain via TXT records (needed for wildcards)
  - **tls-alpn-01**: Via ALPN on port 443
- **Chain/Intermediate**: Always include the CA chain so clients can build trust. Use `fullchain.pem` with Nginx.
- **Private key**: Keep secret, PEM-encoded. Never commit to version control.

### ACME on Windows: win-acme (wacs.exe) quickstart
- Download win-acme from `https://www.win-acme.com/` and run `wacs.exe` as Administrator.
- Common flows:
  - **http-01 (simple)**: Temporarily allow `/.well-known/acme-challenge/` on port 80.
  - **dns-01 (wildcards)**: Use your DNS provider API; wacs has plugins for many providers.
- Output files: choose to save as PEM; point Nginx to `fullchain.pem` and `privkey.pem`.
- Renewal: win-acme schedules a task; ensure Nginx reloads after renewal (see below).

### PEM vs PFX on Windows
- **Nginx uses OpenSSL PEM files** (`.key`, `.crt`/`fullchain.pem`).
- **Windows/IIS often uses PFX** (`.pfx`). You can convert if needed:
```bash
# PFX → PEM key and cert
openssl pkcs12 -in cert.pfx -nodes -out certs_and_key.pem
# Split into key and cert chain if combined
openssl pkey -in certs_and_key.pem -out privkey.pem
openssl crl2pkcs7 -nocrl -certfile certs_and_key.pem | openssl pkcs7 -print_certs -out fullchain.pem
```

## Nginx configuration essentials (Windows build)
Files of interest in this folder:
- `conf\nginx.conf` (main config)
- `cert\` (conventionally store `fullchain.pem` and `privkey.pem` here)

### Minimal HTTP → HTTPS redirect server
```nginx
server {
    listen       80;
    listen       [::]:80;
    server_name  example.com www.example.com;

    # Redirect all cleartext traffic to HTTPS
    return 301 https://$host$request_uri;
}
```

### Basic HTTPS server with SNI
```nginx
server {
    listen              443 ssl;
    listen              [::]:443 ssl;
    server_name         example.com www.example.com;

    ssl_certificate     cert/fullchain.pem;   # include intermediate(s)
    ssl_certificate_key cert/privkey.pem;     # private key

    # Recommended modern TLS settings (adjust to your policy)
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         EECDH+AESGCM:EECDH+CHACHA20;  # OpenSSL modern ciphers
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;

    # OCSP stapling (requires valid chain and resolver)
    ssl_stapling        on;
    ssl_stapling_verify on;
    resolver            1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout    5s;

    # HSTS (uncomment after confirming HTTPS works everywhere)
    # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    root   html;
    index  index.html;
}
```

### Enable ACME http-01 challenge while redirecting
```nginx
server {
    listen       80;
    listen       [::]:80;
    server_name  example.com www.example.com;

    # Allow ACME challenges in plain HTTP
    location ^~ /.well-known/acme-challenge/ {
        root html;   # or a dedicated path where ACME client writes tokens
        default_type text/plain;
    }

    # Everything else goes to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}
```

### Multiple domains on one IP (two server blocks)
```nginx
# example.com cert
server {
    listen 443 ssl;
    server_name example.com www.example.com;
    ssl_certificate     cert/example-fullchain.pem;
    ssl_certificate_key cert/example-privkey.pem;
    # ... app/location blocks ...
}

# anotherdomain.com cert
server {
    listen 443 ssl;
    server_name anotherdomain.com www.anotherdomain.com;
    ssl_certificate     cert/another-fullchain.pem;
    ssl_certificate_key cert/another-privkey.pem;
    # ... app/location blocks ...
}
```

## Certificate lifecycle: obtain, install, renew
1. **Obtain**
   - ACME client (e.g., win-acme, Certbot in WSL, lego, acme.sh)
   - For wildcards, use **dns-01** with API credentials on your DNS provider
   - Ensure **CAA** records allow your CA (or omit if unsure)
2. **Install**
   - Place `fullchain.pem` and `privkey.pem` under `cert\`
   - Point `ssl_certificate` to the full chain and `ssl_certificate_key` to the private key
3. **Reload**
   - On Windows, restart or reload nginx. If `nginx.exe` is running:
```powershell
# From the Nginx directory
./nginx.exe -t   # test config
./nginx.exe -s reload
```
4. **Renew**
   - Automate ACME renewal (task scheduler, service)
   - After renewal, reload Nginx so it picks up the new files
   - With win-acme: enable the built-in scheduled task and add a post-renew script
```powershell
# Example post-renew PowerShell script (reload Nginx if certs updated)
$nginx = Join-Path $PSScriptRoot 'nginx.exe'
& $nginx -t
if ($LASTEXITCODE -eq 0) { & $nginx -s reload }
```
   - With Certbot in WSL: use a Windows scheduled task that invokes `wsl certbot renew --quiet` then reload Nginx

## Security hardening tips
- **Use modern TLS only**: Prefer TLS 1.2/1.3, disable old protocols and weak ciphers.
- **Enable OCSP stapling**: Faster and more private revocation checks for clients.
- **HSTS**: Enforce HTTPS, but deploy cautiously to avoid lockouts.
- **Redirect HTTP → HTTPS**: Don’t serve mixed content.
- **Least privilege on key files**: Restrict filesystem permissions for `privkey.pem`.
- **Set `server_name` correctly**: Prevent default vhost from serving wrong site/cert.
- **Firewall**: Allow inbound 80/443; restrict others. Consider Windows Defender Firewall rules.
- **File permissions on keys (Windows)**: Limit read access to the account running Nginx (e.g., `icacls cert\privkey.pem /inheritance:r /grant YourUser:R`).

## DNS and certificate troubleshooting
- **Is DNS correct?**
```powershell
Resolve-DnsName example.com -Type A,AAAA,CNAME,CAA,TXT
```
- **Is Nginx serving the right cert?**
```bash
openssl s_client -connect example.com:443 -servername example.com -showcerts < /dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```
- **Follow redirects/inspect TLS with curl**
```bash
curl -Iv https://example.com/
curl -I http://example.com/  # should be 301 → https
```
- **Force a hostname against a specific IP (SNI test)**
```bash
curl -Iv --resolve example.com:443:203.0.113.10 https://example.com/
```
- **Common gotchas**
  - Wrong `server_name` or missing `listen 443 ssl;`
  - Using cert file without intermediate (use `fullchain.pem`)
  - DNS still pointing to old IP (check TTL/propagation)
  - CDN/WAF fronting origin with mismatched hostnames
  - Mixed content breaks lock icon (load assets via https)

## Choosing DNS record strategies
- **Apex points to your server**: A/AAAA at `example.com`. If using a dynamic target (e.g., managed LB), prefer ALIAS/ANAME if your provider supports it.
- **Subdomains use CNAME to provider**: `www → yourapp.hosted.example.net` managed by provider.
- **Split-horizon or private DNS**: Internal users resolve to private IPs; public users to public IPs.
- **Geo/DNS-based load balancing**: Some providers route to nearest region; ensure consistent cert coverage for all names.

## Example: end-to-end checklist
- Register domain and set authoritative nameservers at your registrar.
- Create DNS records:
  - `A`/`AAAA` for apex to your server IP(s)
  - `CNAME` for `www` to apex (or to a provider hostname)
  - Optional: `CAA` to restrict CAs; `TXT` for ACME/ownership
- Open firewall ports 80 and 443 to the world; lock down others.
- Obtain certificate (ACME or purchased), ensuring it covers all hostnames.
- Place `fullchain.pem` and `privkey.pem` under `cert\` and update `conf\nginx.conf` server blocks.
- Test config and reload Nginx.
- Verify with `curl -Iv`, `openssl s_client`, and browser.
- Automate renewals; monitor expiry and uptime.

## References (keep handy)
- DNS record help: your DNS provider’s docs (look up “A, AAAA, CNAME, ALIAS/ANAME, TTL, CAA”).
- ACME clients for Windows: `win-acme` (`https://www.win-acme.com/`), `acme.sh` (`https://acme.sh`) [often via Git Bash], Certbot (WSL).
- Mozilla TLS config generator: `https://ssl-config.mozilla.org/` (use as guidance, then adapt to Windows Nginx).



