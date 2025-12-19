# Module Installation Path Fix

## Issue

During development, we discovered that the Makefile was installing the module to the wrong location (`/etc/nginx/modules/`), and manual copying was required after each build.

## Root Cause

Nginx's `load_module` directive uses paths relative to the compiled prefix. When using:

```nginx
load_module modules/ngx_http_hijinx_module.so;
```

Nginx resolves `modules/` relative to its prefix. In most nginx installations (including Debian/Ubuntu packages), the prefix is `/usr/share/nginx`, so this resolves to:

```
/usr/share/nginx/modules/ngx_http_hijinx_module.so
```

The Makefile was incorrectly using `/etc/nginx/modules` as the installation directory.

## How to Verify Your Nginx Prefix

Check your nginx's compiled prefix:

```bash
sudo nginx -V 2>&1 | grep -o "prefix=[^ ]*"
```

Example output:
```
--prefix=/usr/share/nginx
```

The modules directory will be: `{prefix}/modules/`

## Fix Applied

### Makefile Changes

Changed the default `INSTALL_DIR` variable from:
```makefile
INSTALL_DIR ?= /etc/nginx/modules
```

To:
```makefile
INSTALL_DIR ?= /usr/share/nginx/modules
```

### Documentation Updates

Updated the following files to reflect correct installation paths:

1. **README.md** - Updated build instructions with correct module path and note about prefix resolution
2. **INSTALL.md** - Added "Module Installation Paths" section explaining where everything gets installed
3. **Makefile** - Fixed INSTALL_DIR and improved install output messages

## Module Loading Methods

### Method 1: modules-enabled (Recommended)

The `make install` command creates:
- `/etc/nginx/modules-available/mod_http_hijinx.conf` (the load directive)
- `/etc/nginx/modules-enabled/mod_http_hijinx.conf` (symlink to the above)

In your `nginx.conf`:
```nginx
include /etc/nginx/modules-enabled/*.conf;
```

This allows easy enable/disable by creating/removing the symlink.

### Method 2: Direct Load

In your `nginx.conf`:
```nginx
load_module modules/ngx_http_hijinx_module.so;
```

The relative path `modules/` resolves to `/usr/share/nginx/modules/`.

## Installation Paths Summary

After running `make install`, files are installed to:

| Component | Path |
|-----------|------|
| Module binary | `/usr/share/nginx/modules/ngx_http_hijinx_module.so` |
| Load config | `/etc/nginx/modules-available/mod_http_hijinx.conf` |
| Load symlink | `/etc/nginx/modules-enabled/mod_http_hijinx.conf` |
| Patterns file | `/etc/nginx/hijinx/patterns.txt` |
| HTML files | `/etc/nginx/hijinx/html/*.html` |
| Blacklist | `/etc/nginx/hijinx/blacklist.txt` |
| Config templates | `/etc/nginx/hijinx/*.conf` |
| Logs | `/var/log/nginx/hijinx/` |
| Logrotate | `/etc/logrotate.d/hijinx` |

## Testing

Verify the module is correctly installed and loadable:

```bash
# Check module exists
ls -lh /usr/share/nginx/modules/ngx_http_hijinx_module.so

# Check load config
cat /etc/nginx/modules-enabled/mod_http_hijinx.conf

# Test nginx configuration
sudo nginx -t

# Should output:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful
```

## Notes for Different Distributions

Some nginx installations may use different paths:

- **Debian/Ubuntu packages**: `/usr/share/nginx` (prefix)
- **CentOS/RHEL packages**: May use `/usr/lib64/nginx` or `/usr/libexec/nginx`
- **Compiled from source**: Depends on `--prefix` configure option

Always verify your nginx prefix with `nginx -V` and adjust the Makefile's `INSTALL_DIR` accordingly if needed:

```bash
make install INSTALL_DIR=/custom/path/to/modules
```
