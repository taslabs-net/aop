# cfaop

Cloudflare Authenticated Origin Pulls (AOP) CLI tool.

## Setup

```bash
export CLOUDFLARE_API_TOKEN="your-token"
pip install requests
```

## Usage

```bash
./cfaop.py setup                    # Interactive wizard (recommended)
./cfaop.py ZONE_ID                  # Show status
./cfaop.py ZONE_ID --set-aop        # Enable AOP
./cfaop.py ZONE_ID --unset-aop      # Disable AOP
./cfaop.py ZONE_ID --set-aop --dry-run  # Preview changes
./cfaop.py ZONE_ID --troubleshoot   # Diagnose issues
./cfaop.py --help                   # Full documentation
```

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

## Testing

```bash
python3 -m unittest test_cfaop
```

## Support

rc-commerce@cloudflare.com
