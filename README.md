# cfaop

Cloudflare Authenticated Origin Pulls (AOP) CLI tool.

## Install

```bash
curl -O https://raw.githubusercontent.com/taslabs-net/aop/main/cfaop.py
chmod +x cfaop.py
pip install requests
```

## Authenticate

```bash
# Choose one method:
export CLOUDFLARE_API_TOKEN="your-token"          # API Token (recommended)
# OR
export CLOUDFLARE_API_KEY="your-global-api-key"   # Global API Key
export CLOUDFLARE_EMAIL="you@example.com"         # + Account Email
```

Get credentials: https://dash.cloudflare.com/profile/api-tokens

## Usage

```bash
./cfaop.py setup                        # Interactive wizard (recommended)
./cfaop.py ZONE_ID                      # Show status
./cfaop.py ZONE_ID --set-aop            # Enable AOP
./cfaop.py ZONE_ID --unset-aop          # Disable AOP
./cfaop.py ZONE_ID --set-aop --dry-run  # Preview changes
./cfaop.py ZONE_ID --troubleshoot       # Diagnose issues
./cfaop.py --help                       # Full documentation
```

Find your Zone ID: Cloudflare Dashboard → Domain → Overview → right sidebar

## After Enabling AOP

Configure your origin to require client certificates:

```bash
curl -o cloudflare-ca.pem https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem
```

**NGINX:**
```nginx
ssl_client_certificate /path/to/cloudflare-ca.pem;
ssl_verify_client on;
```

**Apache:**
```apache
SSLCACertificateFile /path/to/cloudflare-ca.pem
SSLVerifyClient require
```

## Support

rc-commerce@cloudflare.com
