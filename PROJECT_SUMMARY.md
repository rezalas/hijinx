# Hijinx Nginx Module - Project Summary

## Overview

This is a production-ready nginx C module that provides real-time security monitoring and automatic IP blacklisting.

## Quick Start

```bash
# 1. Build the module
make all NGINX_DIR=/path/to/nginx-source

# 2. Configure nginx
load_module modules/ngx_http_hijinx_module.so;

http {
    hijinx on;
    hijinx_blacklist /etc/nginx/hijinx/blacklist.txt;
    hijinx_log_dir /var/log/nginx/hijinx;
    hijinx_threshold 5;
}

# 3. Reload nginx
sudo nginx -s reload
```

## Key Features

- **Real-time Detection**: Processes requests as they happen
- **Automatic Blocking**: IPs over threshold are immediately blacklisted  
- **High Performance**: Native C code, in-memory tracking
- **Scalable**: Uses shared memory across worker processes
- **Configurable**: Customizable threshold and patterns
- **Production Ready**: Thread-safe, tested, documented

## How It Works

1. **Access Phase**: Checks if IP is blacklisted, detects suspicious patterns
2. **Log Phase**: After request completes, checks status code (403/404)
3. **Tracking**: Increments IP counter in shared memory
4. **Blacklisting**: When threshold reached, adds IP to blacklist
5. **Logging**: Records all blacklisting events with timestamps

## Detected Patterns

- Attempts to access `/admin` or `/login` → 403/404
- Attempts to access `.php` files → 403/404
- Threshold-based (default: 5 attempts)

## Performance Benefits

- **Real-time protection** (no delay)
- **Lower CPU usage** (no log parsing)
- **Better scalability** (in-memory state)

## Configuration Directives

| Directive | Default | Description |
|-----------|---------|-------------|
| `hijinx` | off | Enable/disable module |
| `hijinx_blacklist` | /etc/nginx/hijinx/blacklist.txt | Blacklist file path |
| `hijinx_log_dir` | /var/log/nginx/hijinx | Log directory |
| `hijinx_patterns` | /etc/nginx/hijinx/patterns.txt | Patterns file path |
| `hijinx_threshold` | 5 | Requests before blocking |

## Testing

```bash
# Make suspicious requests
for i in {1..6}; do
    curl http://localhost/admin
done

# Check blacklist
cat /etc/nginx/hijinx/blacklist.txt

# View logs
tail -f /var/log/nginx/hijinx/hijinx_*.log
```

## Requirements

- Nginx source code (matching installed version)
- C compiler (gcc/clang)
- make
- Root/sudo access for installation

## Getting Started

1. Review the documentation (start with README.md)
2. Follow INSTALL.md to build and install
3. Configure nginx with your preferences
4. Test with suspicious requests
5. Monitor logs and blacklist
