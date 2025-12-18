# Hijinx Random Content Serving

## Overview

The random content serving feature allows hijinx to serve misleading HTML content to suspicious requests instead of allowing them through or returning 404 errors. This makes it significantly harder for attackers to profile your site structure and identify vulnerabilities.

## How It Works

When `hijinx_serve_random_content` is enabled, any request matching a suspicious pattern will immediately receive an HTML response randomly selected from your configured HTML directory. This happens before the request reaches your actual application.

### Benefits

1. **Deception**: Attackers see what appears to be legitimate admin panels, login forms, or system dashboards
2. **Protection**: Suspicious requests never reach your real application
3. **Information Hiding**: Your actual site structure remains hidden
4. **Time Wasting**: Attackers waste time analyzing fake content
5. **Detection**: You can monitor which fake pages are being accessed most often

## Configuration

### Basic Setup

```nginx
http {
    hijinx on;
    hijinx_serve_random_content on;
    hijinx_patterns /etc/nginx/hijinx/patterns.txt;
    hijinx_html_dir /etc/nginx/hijinx/html;
    hijinx_threshold 5;
}
```

### Per-Location Configuration

You can enable random content serving for specific locations:

```nginx
server {
    listen 80;
    server_name example.com;
    
    # Disable for legitimate admin area
    location /real-admin {
        hijinx_serve_random_content off;
        # Your real admin config
    }
    
    # Enable for everything else
    location / {
        hijinx on;
        hijinx_serve_random_content on;
    }
}
```

## HTML Files

### Included Examples

Hijinx includes several pre-made HTML files:

1. **admin-login.html** - Generic admin login page with modern styling
2. **wordpress-admin.html** - Realistic WordPress wp-admin login page
3. **phpmyadmin.html** - phpMyAdmin database interface
4. **server-status.html** - Server monitoring dashboard with fake metrics

### Creating Custom HTML

You can create your own HTML files to serve. Simply place them in the HTML directory (default: `/etc/nginx/hijinx/html/`).

#### Requirements

- Files must have `.html` extension
- Maximum 50 HTML files
- Files should be self-contained (inline CSS/JS preferred)
- Keep file sizes reasonable (< 100KB recommended)

#### Example Custom HTML

```html
<!DOCTYPE html>
<html>
<head>
    <title>Database Manager</title>
    <style>
        body { font-family: Arial; background: #f5f5f5; }
        .container { max-width: 800px; margin: 50px auto; }
        .panel { background: white; padding: 30px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="panel">
            <h1>Database Administration</h1>
            <form action="/db/login" method="post">
                <input type="text" name="username" placeholder="Username">
                <input type="password" name="password" placeholder="Password">
                <button type="submit">Connect</button>
            </form>
        </div>
    </div>
</body>
</html>
```

Save this as `/etc/nginx/hijinx/html/database-admin.html` and it will automatically be included in the random rotation after reloading nginx.

### Installation

HTML files are automatically installed by the Makefile:

```bash
make setup
```

This creates the `/etc/nginx/hijinx/html/` directory and copies all HTML files.

### Manual Installation

```bash
# Create directory
sudo mkdir -p /etc/nginx/hijinx/html

# Copy HTML files
sudo cp html/*.html /etc/nginx/hijinx/html/

# Set permissions
sudo chmod 644 /etc/nginx/hijinx/html/*.html
sudo chown -R nginx:nginx /etc/nginx/hijinx
```

## Behavior

### Request Flow

```
Suspicious Request
       ↓
Pattern Match?
       ↓ YES
serve_random_content enabled?
       ↓ YES
Randomly select HTML file
       ↓
Serve HTML with 200 OK
       ↓
Request ends (never reaches app)
```

### Random Selection

HTML files are selected using a simple algorithm:

```
index = (current_time + connection_number) % total_html_files
```

This ensures:
- Different responses for different requests
- Unpredictable from attacker's perspective
- Fast computation
- Even distribution over time

## Testing

### Test Random Content Serving

```bash
# Make requests to suspicious paths
curl -i http://localhost/admin
curl -i http://localhost/wp-login.php
curl -i http://localhost/phpmyadmin

# Each should return 200 OK with random HTML content
```

### Verify HTML Loading

Check nginx error log after reload:

```bash
sudo nginx -s reload
sudo grep "hijinx: loaded.*HTML files" /var/log/nginx/error.log
```

You should see:
```
hijinx: loaded 4 HTML files from /etc/nginx/hijinx/html
```

## Performance

### Resource Usage

- **Memory**: HTML files are loaded into memory at startup
  - 4 example files ≈ 25KB total
  - 50 files × 100KB = ~5MB maximum
- **CPU**: Minimal overhead (< 1% increase)
- **Speed**: Faster than proxying to real application

### Optimization Tips

1. **Keep HTML small**: Inline CSS/JS, optimize images
2. **Limit quantity**: Only include what you need
3. **Pre-gzip**: Consider serving pre-compressed content
4. **Cache headers**: HTML is static, can be cached

## Security Considerations

### What to Include

**Good candidates for fake content:**
- Generic admin panels
- Database management interfaces
- Server monitoring dashboards
- Login pages
- Configuration panels

### What to Avoid

**Don't include:**
- Real company branding (could confuse legitimate users)
- Actual login forms that submit to your domain
- Content that could be legally problematic
- Malicious code or exploits

### Best Practices

1. **Make it believable**: Use realistic styling and common frameworks
2. **Vary content**: Include different types of fake pages
3. **Monitor logs**: Watch what attackers are looking for
4. **Update regularly**: Change fake content periodically
5. **Test thoroughly**: Ensure no information leakage

## Troubleshooting

### No HTML files loaded

**Error**: `hijinx: no HTML files found in /etc/nginx/hijinx/html`

**Solution**: 
```bash
# Verify directory exists
ls -la /etc/nginx/hijinx/html/

# Run setup to install default files
make setup
```

### Still seeing 404s

**Check**: Is `hijinx_serve_random_content` enabled?

```bash
# Verify in your nginx config
grep hijinx_serve_random_content /etc/nginx/nginx.conf
```

### Memory errors

**Error**: Failed to allocate memory for HTML

**Solution**: Reduce number of HTML files or file sizes

```bash
# Check current usage
ls -lh /etc/nginx/hijinx/html/

# Remove unnecessary files
sudo rm /etc/nginx/hijinx/html/large-file.html
```

## Examples

### Scenario 1: WordPress Site (Not Using WP)

```nginx
server {
    server_name myblog.com;
    
    hijinx on;
    hijinx_serve_random_content on;
    hijinx_patterns /etc/nginx/hijinx/patterns-wordpress.txt;
    
    # Patterns include:
    # /wp-admin
    # /wp-login.php
    # /xmlrpc.php
    
    # Attackers see fake WordPress admin
    # Your actual site (non-WP) is protected
}
```

### Scenario 2: API Server

```nginx
server {
    server_name api.example.com;
    
    location /api {
        # Real API, no hijinx
        proxy_pass http://backend;
    }
    
    location / {
        # Everything else gets fake content
        hijinx on;
        hijinx_serve_random_content on;
    }
}
```

### Scenario 3: Multiple Sites

```nginx
http {
    hijinx on;
    hijinx_threshold 3;
    
    server {
        server_name public.example.com;
        hijinx_serve_random_content on;  # Serve fake content
    }
    
    server {
        server_name internal.example.com;
        hijinx_serve_random_content off;  # Standard mode
    }
}
```

## Monitoring

### Check What's Being Served

Random content serving is logged to `/var/log/nginx/hijinx/hijinx.log`:

```bash
# Watch real-time random content serving
tail -f /var/log/nginx/hijinx/hijinx.log | grep "Served random content"
```

Example log entries:
```
2025-12-18 14:30:22 - 192.168.1.100 - Served random content (file #2) - /admin
2025-12-18 14:31:45 - 10.0.0.50 - Served random content (file #0) - /wp-login.php
2025-12-18 14:32:10 - 172.16.0.25 - Served random content (file #3) - /phpmyadmin
```

The log shows:
- **Timestamp**: When the request was made
- **IP Address**: Who made the request
- **File Index**: Which HTML file was served (0-based)
- **URI**: What path they requested

### Error Monitoring

Check for errors in the hijinx error log:

```bash
tail -f /var/log/nginx/hijinx/hijinx-error.log
```

Common errors:
- No HTML files loaded
- Failed to allocate memory
- Failed to open log files

### Log Analysis

Analyze which fake content is most popular:

```bash
# Count requests by file index
grep "Served random content" /var/log/nginx/hijinx/hijinx.log | \
  sed 's/.*file #\([0-9]*\).*/\1/' | sort | uniq -c | sort -rn

# Count requests by IP
grep "Served random content" /var/log/nginx/hijinx/hijinx.log | \
  awk '{print $4}' | sort | uniq -c | sort -rn

# Show most commonly attacked paths
grep "Served random content" /var/log/nginx/hijinx/hijinx.log | \
  awk -F' - ' '{print $NF}' | sort | uniq -c | sort -rn
```

## Advanced Usage

### Dynamic Content

For truly dynamic fake content, consider using SSI or nginx variables:

```html
<!DOCTYPE html>
<html>
<head><title>Server Status</title></head>
<body>
    <h1>Server Status</h1>
    <p>Current time: <!--#echo var="date_local" --></p>
    <p>Server: <!--#echo var="hostname" --></p>
</body>
</html>
```

### Honeypot Integration

Combine with honeypot logging to track attacker behavior:

```nginx
location /admin {
    hijinx on;
    hijinx_serve_random_content on;
    
    # Log all access to fake admin
    access_log /var/log/nginx/honeypot.log combined;
}
```

## Summary

The random content serving feature provides:

- **Immediate deception** for suspicious requests
- **Zero configuration** with included HTML examples
- **Easy customization** with your own HTML files
- **Performance** with in-memory caching
- **Flexibility** with per-location control

Perfect for sites that want to waste attackers' time while protecting their real application structure.
