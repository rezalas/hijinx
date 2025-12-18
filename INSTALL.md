# Hijinx Module - Installation Guide

This guide walks you through building and installing the hijinx nginx module from source.

## Prerequisites

- nginx source code (same version as your installed nginx)
- C compiler (gcc or clang)
- make
- Root/sudo access

## Quick Start

If you have nginx source already:

```bash
# 1. Setup directories and permissions
make setup

# 2. Configure nginx with the module
make config NGINX_DIR=/path/to/nginx-source

# 3. Build the module
make build

# 4. Install the module
make install
```

Or all at once:
```bash
make all NGINX_DIR=/path/to/nginx-source
```

## Detailed Installation Steps

### Step 1: Get Nginx Source Code

First, find out your current nginx version:
```bash
nginx -v
```

Download the matching version:
```bash
# Example for nginx 1.24.0
cd /tmp
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -xzf nginx-1.24.0.tar.gz
```

### Step 2: Configure Nginx with the Module

#### As a Dynamic Module (Recommended)

Dynamic modules can be loaded/unloaded without recompiling nginx:

```bash
cd /tmp/nginx-1.24.0
./configure --add-dynamic-module=/path/to/hijinx
```

If you want to preserve your existing nginx modules, use the same configure options as your current installation. To see your current configure options:

```bash
nginx -V 2>&1 | grep -o 'configure arguments:.*' | cut -d: -f2-
```

Then add `--add-dynamic-module=/path/to/hijinx` to those options:

```bash
./configure [your existing options] --add-dynamic-module=/path/to/hijinx
```

#### As a Static Module

If you prefer a static module (compiled into nginx):

```bash
cd /tmp/nginx-1.24.0
./configure --add-module=/path/to/hijinx [other options]
```

### Step 3: Build the Module

#### For Dynamic Module:
```bash
make modules
```

This creates: `objs/ngx_http_hijinx_module.so`

#### For Static Module:
```bash
make
sudo make install
```

This rebuilds and reinstalls nginx with the module compiled in.

### Step 4: Install the Dynamic Module

Copy the module to your nginx modules directory:

```bash
sudo mkdir -p /etc/nginx/modules
sudo cp objs/ngx_http_hijinx_module.so /etc/nginx/modules/
```

### Step 5: Setup Directories and Files

Create the required directories and files:

```bash
# Create directories
sudo mkdir -p /etc/nginx/hijinx
sudo mkdir -p /var/log/nginx/hijinx

# Create blacklist file
sudo touch /etc/nginx/hijinx/blacklist.txt

# Set permissions (adjust user based on your system)
# For systems using 'nginx' user:
sudo chown -R nginx:nginx /etc/nginx/hijinx
sudo chown -R nginx:nginx /var/log/nginx/hijinx

# For systems using 'www-data' user (Debian/Ubuntu):
# sudo chown -R www-data:www-data /etc/nginx/hijinx
# sudo chown -R www-data:www-data /var/log/nginx/hijinx

# Set proper permissions
sudo chmod 644 /etc/nginx/hijinx/blacklist.txt
sudo chmod 755 /etc/nginx/hijinx
sudo chmod 755 /var/log/nginx/hijinx
```

Or use the Makefile:
```bash
make setup
```

### Step 6: Configure Nginx

#### For Dynamic Module:

Add to the **top** of your `nginx.conf` (before any other directives):

```nginx
load_module modules/ngx_http_hijinx_module.so;
```

Then add the hijinx configuration in your `http` block:

```nginx
http {
    # Enable hijinx
    hijinx on;
    
    # Configure paths
    hijinx_blacklist /etc/nginx/hijinx/blacklist.txt;
    hijinx_log_dir /var/log/nginx/hijinx;
    
    # Set threshold (number of suspicious requests before blocking)
    hijinx_threshold 5;
    
    # ... rest of your configuration
}
```

#### For Static Module:

No need for `load_module`. Just add the configuration:

```nginx
http {
    hijinx on;
    hijinx_blacklist /etc/nginx/hijinx/blacklist.txt;
    hijinx_log_dir /var/log/nginx/hijinx;
    hijinx_threshold 5;
    
    # ... rest of your configuration
}
```

### Step 7: Test and Reload

Test the configuration:
```bash
sudo nginx -t
```

If successful, reload nginx:
```bash
sudo nginx -s reload
```

Or restart:
```bash
sudo systemctl restart nginx
```

## Verification

### Check if Module is Loaded

For dynamic modules:
```bash
nginx -V 2>&1 | grep hijinx
```

### Test the Module

Make some suspicious requests:
```bash
# Try to access admin (should trigger detection)
curl http://localhost/admin
curl http://localhost/admin
curl http://localhost/admin
curl http://localhost/admin
curl http://localhost/admin

# After threshold is reached, should get 403
curl http://localhost/admin
```

Check the logs:
```bash
# Check hijinx log
tail -f /var/log/nginx/hijinx/hijinx.log

# Check blacklist
cat /etc/nginx/hijinx/blacklist.txt

# Check nginx error log
sudo tail -f /var/log/nginx/error.log | grep hijinx
```

### Setup Log Rotation

Install the logrotate configuration:
```bash
sudo cp logrotate-hijinx.conf /etc/logrotate.d/hijinx
sudo chmod 644 /etc/logrotate.d/hijinx
```

Test it:
```bash
sudo logrotate -d /etc/logrotate.d/hijinx
```

## Troubleshooting

### Module doesn't load

**Error**: "unknown directive hijinx"

**Solution**: 
- For dynamic module: Ensure `load_module` is at the top of nginx.conf
- Verify module file exists: `ls -la /etc/nginx/modules/ngx_http_hijinx_module.so`
- Check nginx error log: `sudo tail -f /var/log/nginx/error.log`

### Compilation errors

**Error**: "nginx.h: No such file or directory"

**Solution**: Make sure you're running configure/make from the nginx source directory

**Error**: "undefined reference to ngx_*"

**Solution**: Use nginx source code that matches your installed nginx version

### Permission errors

**Error**: "open() /etc/nginx/hijinx/blacklist.txt failed (13: Permission denied)"

**Solution**:
```bash
# Check nginx user
ps aux | grep nginx

# Set ownership (replace 'nginx' with your nginx user)
sudo chown nginx:nginx /etc/nginx/hijinx/blacklist.txt
sudo chown -R nginx:nginx /var/log/nginx/hijinx
```

### Shared memory errors

**Error**: "hijinx_zone already exists"

**Solution**: Restart nginx (not just reload) to clear shared memory:
```bash
sudo systemctl restart nginx
```

### IPs not being blocked

**Checklist**:
1. Module is enabled: `hijinx on;`
2. Directories exist and are writable
3. Threshold is set appropriately
4. Requests match suspicious patterns
5. Responses return 403 or 404

**Debug**:
```bash
# Enable debug logging in nginx
error_log /var/log/nginx/error.log debug;

# Restart and check logs
sudo nginx -s reload
sudo tail -f /var/log/nginx/error.log
```

## Uninstalling

### Remove Dynamic Module

```bash
# Remove load_module line from nginx.conf
sudo nano /etc/nginx/nginx.conf

# Remove the module file
sudo rm /etc/nginx/modules/ngx_http_hijinx_module.so

# Reload nginx
sudo nginx -s reload
```

### Remove Configuration and Data

```bash
# Remove hijinx configuration from nginx.conf
sudo nano /etc/nginx/nginx.conf

# Remove directories
sudo rm -rf /etc/nginx/hijinx
sudo rm -rf /var/log/nginx/hijinx

# Reload nginx
sudo nginx -s reload
```

## Alternative: Docker Installation

If you're using nginx in Docker, you'll need to build a custom image:

```dockerfile
FROM nginx:1.24.0

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    wget

# Download nginx source
WORKDIR /tmp
RUN wget http://nginx.org/download/nginx-1.24.0.tar.gz && \
    tar -xzf nginx-1.24.0.tar.gz

# Copy module source
COPY . /tmp/hijinx

# Build module
WORKDIR /tmp/nginx-1.24.0
RUN ./configure --add-dynamic-module=/tmp/hijinx && \
    make modules && \
    cp objs/ngx_http_hijinx_module.so /etc/nginx/modules/

# Setup directories
RUN mkdir -p /etc/nginx/hijinx /var/log/nginx/hijinx && \
    touch /etc/nginx/hijinx/blacklist.txt && \
    chown -R nginx:nginx /etc/nginx/hijinx /var/log/nginx/hijinx

# Clean up
RUN apt-get remove -y build-essential wget && \
    apt-get autoremove -y && \
    rm -rf /tmp/*

WORKDIR /
```

Build and run:
```bash
docker build -t nginx-hijinx .
docker run -d -p 80:80 -v /path/to/nginx.conf:/etc/nginx/nginx.conf nginx-hijinx
```

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review nginx error logs: `/var/log/nginx/error.log`
3. Review hijinx logs: `/var/log/nginx/hijinx/`
4. Check file permissions and ownership
