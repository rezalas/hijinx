# Hijinx Nginx Module

## What is Hijinx?

Hijinx is a security tool for processing requests on web servers to make life less interesting for people that get a bit too curious. The way it works is by redirecting requests from suspicious sources to 404, or serving them misleading content (dealers choice - like a fake login page). If an IP address makes too many suspicious This conf file sets up the necessary rules to achieve that.

## Overview

This module processes requests in real-time. It monitors for suspicious patterns and automatically blacklists IPs that exceed a configurable threshold.

## Features

- **Real-time monitoring**: Processes requests as they happen
- **Automatic blacklisting**: IPs exceeding the suspicion threshold are automatically added to the blacklist
- **Configurable patterns**: Detects attempts to access:
  - `/admin` paths
  - `/login` paths
  - `.php` files
- **Shared memory**: Uses nginx shared memory for efficient IP tracking across worker processes
- **Detailed logging**: Maintains logs of blacklisted IPs with timestamps

## Building the Module

### As a Dynamic Module

```bash
# Configure nginx with the module
./configure --add-dynamic-module=/path/to/hijinx

# Build
make modules

# Install
sudo cp objs/ngx_http_hijinx_module.so /etc/nginx/modules/
```

### As a Static Module

```bash
# Configure nginx with the module
./configure --add-module=/path/to/hijinx

# Build and install
make
sudo make install
```

## Configuration

### Load the Module (Dynamic Module Only)

Add to the top of your `nginx.conf`:

```nginx
load_module modules/ngx_http_hijinx_module.so;
```

### Basic Configuration

```nginx
http {
    # Enable the module
    hijinx on;
    
    # Configure paths and threshold
    hijinx_blacklist /etc/nginx/hijinx/blacklist.txt;
    hijinx_log_dir /var/log/nginx/hijinx;
    hijinx_threshold 5;
    
    server {
        listen 80;
        server_name example.com;
        
        location / {
            # Module is active here
            root /var/www/html;
        }
    }
}
```

### Configuration Directives

#### `hijinx`
- **Syntax**: `hijinx on|off;`
- **Default**: `off`
- **Context**: `http`, `server`, `location`

Enables or disables the hijinx module.

#### `hijinx_blacklist`
- **Syntax**: `hijinx_blacklist path;`
- **Default**: `/etc/nginx/hijinx/blacklist.txt`
- **Context**: `http`, `server`, `location`

Path to the blacklist file where blocked IPs are stored.

#### `hijinx_log_dir`
- **Syntax**: `hijinx_log_dir path;`
- **Default**: `/var/log/nginx/hijinx`
- **Context**: `http`, `server`, `location`

Directory where hijinx logs are written.

#### `hijinx_threshold`
- **Syntax**: `hijinx_threshold number;`
- **Default**: `5`
- **Context**: `http`, `server`, `location`

Number of suspicious requests before an IP is blacklisted.

#### `hijinx_patterns`
- **Syntax**: `hijinx_patterns path;`
- **Default**: `/etc/nginx/hijinx/patterns.txt`
- **Context**: `http`, `server`, `location`

Path to the patterns file containing suspicious URI patterns to monitor. See [PATTERNS.md](PATTERNS.md) for detailed documentation.

## How It Works

1. **Access Phase**: The module intercepts requests in the access phase and checks if the IP is already blacklisted. If blacklisted, returns 403 Forbidden immediately.

2. **Pattern Detection**: Examines the request URI against patterns loaded from the patterns file. Default patterns include:
   - `/admin`, `/login` - Admin panel access attempts
   - `.php` - PHP file probing
   - See `patterns.txt` for full list

3. **Log Phase**: After the request is processed, if a suspicious pattern was detected AND the response status is 403 or 404, the IP's suspicion counter is incremented in shared memory.

4. **Automatic Blacklisting**: When an IP reaches the threshold, it's automatically added to the blacklist file and logged.

5. **Shared Memory**: Uses nginx shared memory (10MB by default) to track IP counts across all worker processes.

## Setup Instructions

1. **Create required directories**:
```bash
sudo mkdir -p /etc/nginx/hijinx
sudo mkdir -p /var/log/nginx/hijinx
```

2. **Create blacklist file**:
```bash
sudo touch /etc/nginx/hijinx/blacklist.txt
sudo chmod 644 /etc/nginx/hijinx/blacklist.txt
```

3. **Set permissions**:
```bash
sudo chown -R nginx:nginx /etc/nginx/hijinx
sudo chown -R nginx:nginx /var/log/nginx/hijinx
```

4. **Configure nginx** (see Configuration section above)

5. **Test configuration**:
```bash
sudo nginx -t
```

6. **Reload nginx**:
```bash
sudo nginx -s reload
```

## Advantages

1. **Real-time**: Blocks malicious IPs immediately during request processing
2. **Performance**: Native C code for fast execution
3. **Efficiency**: In-memory tracking, no repeated log parsing
4. **Immediate protection**: Bad actors are blocked on their threshold+1 request
5. **Scalability**: Handles high traffic loads efficiently
6. **Integration**: Works seamlessly with nginx's request processing

## Monitoring

Check the hijinx log:
```bash
tail -f /var/log/nginx/hijinx/hijinx.log
```

View blacklisted IPs:
```bash
cat /etc/nginx/hijinx/blacklist.txt
```

Check nginx error log for module messages:
```bash
tail -f /var/log/nginx/error.log | grep hijinx
```

## Log Rotation

The module writes to a single log file (`hijinx.log`) that can be rotated using standard tools like `logrotate`.

**Install logrotate configuration:**
```bash
sudo cp logrotate-hijinx.conf /etc/logrotate.d/hijinx
sudo chmod 644 /etc/logrotate.d/hijinx
```

**Test the configuration:**
```bash
sudo logrotate -d /etc/logrotate.d/hijinx
```

**Manual rotation (for testing):**
```bash
sudo logrotate -f /etc/logrotate.d/hijinx
```

The default configuration:
- Rotates daily
- Keeps 30 days of logs
- Compresses old logs
- Automatically signals nginx to reopen log files

## Troubleshooting

### Module not loading
- Ensure the module path in `load_module` is correct
- Check nginx error log: `sudo tail /var/log/nginx/error.log`

### IPs not being blacklisted
- Verify threshold is set appropriately
- Check that suspicious patterns are being triggered
- Ensure directories exist and are writable by nginx user
- Check shared memory is initialized: `sudo ipcs -m`

### Permission denied errors
- Verify nginx user has write access to blacklist file and log directory
- Check SELinux/AppArmor policies if applicable

## Example Test

Test the module by making suspicious requests:
```bash
# These should trigger the suspicious pattern detection
curl http://your-server/admin
curl http://your-server/test.php
curl http://your-server/login
# Repeat 5 times (or your threshold value)
```

After reaching the threshold, subsequent requests should return 403 Forbidden.

## License

This module is provided as-is for security enhancement purposes.
