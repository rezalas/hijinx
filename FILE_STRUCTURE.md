# Hijinx File Installation Guide

## Installed Files Overview

After running `make setup` and `make install`, Hijinx installs files to several locations:

### Module Files

```
/etc/nginx/modules/
└── ngx_http_hijinx_module.so          # The compiled module

/etc/nginx/modules-available/
└── mod_http_hijinx.conf                # Module load configuration

/etc/nginx/modules-enabled/
└── mod_http_hijinx.conf -> ../modules-available/mod_http_hijinx.conf  # Symlink
```

### Configuration Files

```
/etc/nginx/hijinx/
├── blacklist.txt                       # IP blacklist (auto-updated)
├── patterns.txt                        # Suspicious URI patterns
├── hijinx-nginx.conf                   # Main configuration template
└── config_template.conf                # Example configuration
```

### Log Files

```
/var/log/nginx/hijinx/
└── hijinx.log                          # Blacklist event log (rotated daily)
```

### System Files

```
/etc/logrotate.d/
└── hijinx                              # Log rotation configuration
```

## Installation Commands

### Full Installation

```bash
# Complete setup and installation
make all NGINX_DIR=/path/to/nginx-source

# Or step by step:
make setup                              # Create directories, install config files
make config NGINX_DIR=/path/to/nginx    # Configure nginx with module
make build                              # Build the module
make install                            # Install module and configs
```

### Individual Components

```bash
make setup        # Install directories and config files only
make logrotate    # Install logrotate config only
make enable       # Enable module (create symlink)
make disable      # Disable module (remove symlink)
```

## File Descriptions

### Module Binary

**`ngx_http_hijinx_module.so`**
- Location: `/etc/nginx/modules/`
- The compiled nginx module
- Loaded by nginx at startup
- Built from `ngx_http_hijinx_module.c`

### Module Configuration

**`mod_http_hijinx.conf`**
- Location: `/etc/nginx/modules-available/`
- Contains: `load_module modules/ngx_http_hijinx_module.so;`
- Purpose: Loads the hijinx module
- Enabled via symlink in `modules-enabled/`

**Enabling/Disabling:**
```bash
# Enable
make enable
# Or manually:
sudo ln -s /etc/nginx/modules-available/mod_http_hijinx.conf \
           /etc/nginx/modules-enabled/mod_http_hijinx.conf

# Disable
make disable
# Or manually:
sudo rm /etc/nginx/modules-enabled/mod_http_hijinx.conf
```

### Configuration Files

**`hijinx-nginx.conf`**
- Location: `/etc/nginx/hijinx/`
- Purpose: Main hijinx configuration directives
- Contains: threshold, log_dir, blacklist, patterns settings
- Include in your nginx.conf or server block

**`config_template.conf`**
- Location: `/etc/nginx/hijinx/`
- Purpose: Example nginx configuration
- Shows how to configure hijinx in nginx.conf
- Reference for setting up hijinx

**`patterns.txt`**
- Location: `/etc/nginx/hijinx/`
- Purpose: List of suspicious URI patterns
- One pattern per line, comments start with #
- Customizable without recompiling module
- See [PATTERNS.md](PATTERNS.md) for details

**`blacklist.txt`**
- Location: `/etc/nginx/hijinx/`
- Purpose: List of blacklisted IPs
- Auto-updated by hijinx module
- One IP per line
- Can be manually edited

### Log Files

**`hijinx.log`**
- Location: `/var/log/nginx/hijinx/`
- Purpose: Records blacklist events
- Format: `YYYY-MM-DD HH:MM:SS - IP - Message - URI`
- Rotated daily by logrotate
- Compressed after rotation

**Logrotate configuration:**
- Location: `/etc/logrotate.d/hijinx`
- Rotation: Daily
- Retention: 30 days
- Compression: Yes (gzip)

## Nginx Configuration

### Method 1: Include Modules-Enabled (Recommended)

In your main `nginx.conf`:

```nginx
# At the top level (before http block)
include /etc/nginx/modules-enabled/*.conf;

http {
    # Include hijinx configuration
    include /etc/nginx/hijinx/hijinx-nginx.conf;
    
    # Your other settings
    server {
        listen 80;
        # ...
    }
}
```

### Method 2: Direct Include

In your main `nginx.conf`:

```nginx
# At the top level
load_module modules/ngx_http_hijinx_module.so;

http {
    hijinx on;
    hijinx_patterns /etc/nginx/hijinx/patterns.txt;
    hijinx_blacklist /etc/nginx/hijinx/blacklist.txt;
    hijinx_log_dir /var/log/nginx/hijinx;
    hijinx_threshold 5;
    
    # Your servers...
}
```

## File Permissions

All files are installed with appropriate permissions:

```bash
# Configuration files
-rw-r--r-- /etc/nginx/hijinx/*.conf
-rw-r--r-- /etc/nginx/hijinx/*.txt

# Module
-rwxr-xr-x /etc/nginx/modules/ngx_http_hijinx_module.so

# Directories
drwxr-xr-x /etc/nginx/hijinx/
drwxr-xr-x /var/log/nginx/hijinx/
```

Owner: `nginx:nginx` or `www-data:www-data` (depending on system)

## Updating Files

### Update Patterns

```bash
# Edit patterns
sudo nano /etc/nginx/hijinx/patterns.txt

# Reload nginx
sudo nginx -s reload
```

### Update Configuration

```bash
# Edit configuration
sudo nano /etc/nginx/hijinx/hijinx-nginx.conf

# Test
sudo nginx -t

# Reload
sudo nginx -s reload
```

### Update Module

```bash
# Rebuild and reinstall
cd /path/to/hijinx
make build
make install

# Restart nginx (not just reload for module changes)
sudo systemctl restart nginx
```

## Verification

Check installed files:

```bash
# Module
ls -la /etc/nginx/modules/ngx_http_hijinx_module.so
ls -la /etc/nginx/modules-available/mod_http_hijinx.conf
ls -la /etc/nginx/modules-enabled/mod_http_hijinx.conf

# Configuration
ls -la /etc/nginx/hijinx/

# Logs
ls -la /var/log/nginx/hijinx/

# Test nginx config
sudo nginx -t

# Check module is loaded
nginx -V 2>&1 | grep hijinx
```

## Uninstallation

```bash
# Disable module
make disable

# Remove files
sudo rm /etc/nginx/modules/ngx_http_hijinx_module.so
sudo rm /etc/nginx/modules-available/mod_http_hijinx.conf
sudo rm /etc/nginx/modules-enabled/mod_http_hijinx.conf
sudo rm -rf /etc/nginx/hijinx/
sudo rm -rf /var/log/nginx/hijinx/
sudo rm /etc/logrotate.d/hijinx

# Remove hijinx config from nginx.conf
sudo nano /etc/nginx/nginx.conf

# Test and reload
sudo nginx -t
sudo nginx -s reload
```

## Troubleshooting

### Module not loading

Check module path:
```bash
ls -la /etc/nginx/modules/ngx_http_hijinx_module.so
```

Check load configuration:
```bash
cat /etc/nginx/modules-enabled/mod_http_hijinx.conf
```

Verify nginx includes modules:
```bash
grep -r "modules-enabled" /etc/nginx/nginx.conf
```

### Files not found

Re-run setup:
```bash
make setup
```

Check permissions:
```bash
ls -la /etc/nginx/hijinx/
```

### Configuration errors

Test configuration:
```bash
sudo nginx -t
```

Check error log:
```bash
sudo tail -f /var/log/nginx/error.log
```

## Summary

| File Type | Source | Destination | Purpose |
|-----------|--------|-------------|---------|
| Module | ngx_http_hijinx_module.c | /etc/nginx/modules/ | Compiled module |
| Mod Conf | mod_http_hijinx.conf | /etc/nginx/modules-available/ | Load directive |
| Symlink | - | /etc/nginx/modules-enabled/ | Enable module |
| Config | hijinx-nginx.conf | /etc/nginx/hijinx/ | Main config |
| Template | config_template.conf | /etc/nginx/hijinx/ | Example config |
| Patterns | patterns.txt | /etc/nginx/hijinx/ | URI patterns |
| Blacklist | - | /etc/nginx/hijinx/ | Blocked IPs |
| Log | - | /var/log/nginx/hijinx/ | Event log |
| Logrotate | logrotate-hijinx.conf | /etc/logrotate.d/ | Rotation config |

All files installed automatically with `make all` or `make setup && make install`.
