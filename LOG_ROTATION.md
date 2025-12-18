# Log Rotation Guide for Hijinx Module

## Overview

The Hijinx module writes all events to a single log file: `/var/log/nginx/hijinx/hijinx.log`

This file should be rotated regularly using standard log rotation tools to prevent it from growing too large.

## Using Logrotate (Recommended)

### Installation

```bash
# Install the provided configuration
sudo cp logrotate-hijinx.conf /etc/logrotate.d/hijinx
sudo chmod 644 /etc/logrotate.d/hijinx
```

Or use the Makefile:
```bash
make logrotate
```

### Configuration

The default configuration (`/etc/logrotate.d/hijinx`) provides:

- **Daily rotation**: Logs rotate every day
- **30-day retention**: Keeps 30 days of historical logs
- **Compression**: Old logs are compressed with gzip
- **Delayed compression**: Delays compression until the next rotation
- **Date suffix**: Rotated files named like `hijinx.log-20251218`
- **Automatic signal**: Sends USR1 signal to nginx to reopen logs

### Testing

Test the configuration without actually rotating:
```bash
sudo logrotate -d /etc/logrotate.d/hijinx
```

Force an immediate rotation (for testing):
```bash
sudo logrotate -f /etc/logrotate.d/hijinx
```

### Customization

Edit `/etc/logrotate.d/hijinx` to customize rotation behavior:

**Change rotation frequency:**
```
# Options: daily, weekly, monthly
weekly
```

**Change retention period:**
```
# Keep 90 days instead of 30
rotate 90
```

**Change compression:**
```
# Disable compression
nocompress

# Or use different compression
compresscmd /usr/bin/xz
compressoptions -9
compressext .xz
```

**Change permissions:**
```
# For Debian/Ubuntu systems using www-data
create 0640 www-data www-data
```

**Change date format:**
```
# Use YYYY-MM-DD format
dateformat -%Y-%m-%d
```

### Verification

Check if logrotate is scheduled:
```bash
# Logrotate usually runs via cron
cat /etc/cron.daily/logrotate

# Or check systemd timer (newer systems)
systemctl list-timers | grep logrotate
```

View rotated logs:
```bash
# List all hijinx logs
ls -lh /var/log/nginx/hijinx/

# View a compressed log
zcat /var/log/nginx/hijinx/hijinx.log-20251218.gz | tail -n 20
```

## Alternative: Manual Rotation

If you don't have logrotate, you can rotate manually:

```bash
#!/bin/bash
# manual-rotate-hijinx.sh

LOG_DIR="/var/log/nginx/hijinx"
LOG_FILE="$LOG_DIR/hijinx.log"
DATE=$(date +%Y%m%d)

# Move current log
mv "$LOG_FILE" "$LOG_FILE-$DATE"

# Tell nginx to reopen log files
nginx -s reopen

# Compress old log
gzip "$LOG_FILE-$DATE"

# Delete logs older than 30 days
find "$LOG_DIR" -name "hijinx.log-*.gz" -mtime +30 -delete
```

Add to cron for daily rotation:
```bash
# Run at 2 AM daily
0 2 * * * /path/to/manual-rotate-hijinx.sh
```

## Using Nginx Log Rotation

You can also let nginx handle rotation using its built-in error_log rotation:

**In nginx.conf:**
```nginx
# This is NOT recommended for hijinx since we use a custom log file
# But included for reference

# Nginx can rotate its own logs when receiving USR1 signal
# Just send: nginx -s reopen
```

The hijinx module doesn't use nginx's error_log facility, so this won't rotate hijinx.log.

## Log Format

Each log entry includes:
```
YYYY-MM-DD HH:MM:SS - IP_ADDRESS - Added to blacklist thanks to final straw - /REQUEST_URI
```

Example:
```
2025-12-18 14:32:15 - 192.168.1.100 - Added to blacklist thanks to final straw - /admin
2025-12-18 14:35:22 - 10.0.0.50 - Added to blacklist thanks to final straw - /test.php
```

## Monitoring Logs

### Real-time monitoring

Watch new entries as they're added:
```bash
tail -f /var/log/nginx/hijinx/hijinx.log
```

### Search logs

Find specific IP:
```bash
grep "192.168.1.100" /var/log/nginx/hijinx/hijinx.log*
```

Count blacklist events today:
```bash
grep "$(date +%Y-%m-%d)" /var/log/nginx/hijinx/hijinx.log | wc -l
```

Find most blocked IPs:
```bash
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' \
  /var/log/nginx/hijinx/hijinx.log* | sort | uniq -c | sort -rn | head -10
```

### Integration with log analysis tools

**With grep/awk:**
```bash
# Extract all IPs added to blacklist
awk '{print $4}' /var/log/nginx/hijinx/hijinx.log

# Count by date
awk '{print $1}' /var/log/nginx/hijinx/hijinx.log | sort | uniq -c
```

**With logwatch:**
Create a custom logwatch script in `/etc/logwatch/scripts/services/hijinx`

**With fail2ban:**
While not necessary (hijinx already blocks), you could integrate for system-wide bans

**With ELK Stack:**
Configure Filebeat to ship logs to Elasticsearch for analysis

## Disk Space Management

### Check log size

```bash
du -sh /var/log/nginx/hijinx/
```

### Estimate growth

```bash
# Size of current log
ls -lh /var/log/nginx/hijinx/hijinx.log

# Entries per day
grep "$(date +%Y-%m-%d)" /var/log/nginx/hijinx/hijinx.log | wc -l

# Average size per entry
du -b /var/log/nginx/hijinx/hijinx.log | awk '{print $1}' | \
  xargs -I {} echo "scale=2; {} / $(wc -l < /var/log/nginx/hijinx/hijinx.log)" | bc
```

### Set up alerts

```bash
# Alert if log directory exceeds 100MB
if [ $(du -sm /var/log/nginx/hijinx | cut -f1) -gt 100 ]; then
    echo "Hijinx logs exceed 100MB!" | mail -s "Log Alert" admin@example.com
fi
```

## Troubleshooting

### Logs not rotating

Check permissions:
```bash
ls -la /var/log/nginx/hijinx/
ls -la /etc/logrotate.d/hijinx
```

Check logrotate status:
```bash
# View last run
cat /var/lib/logrotate/status | grep hijinx

# Check for errors
sudo logrotate -v /etc/logrotate.d/hijinx
```

### Permission denied errors

Ensure nginx user can write to log directory:
```bash
sudo chown nginx:nginx /var/log/nginx/hijinx/hijinx.log
# or for Debian/Ubuntu:
sudo chown www-data:www-data /var/log/nginx/hijinx/hijinx.log
```

### Nginx doesn't reopen log

Verify nginx PID file location in logrotate config matches your system:
```bash
# Common locations:
# /var/run/nginx.pid
# /run/nginx.pid
# /usr/local/nginx/logs/nginx.pid

# Find actual location
ps aux | grep nginx | grep master
```

Update `/etc/logrotate.d/hijinx` with correct path:
```
postrotate
    if [ -f /run/nginx.pid ]; then
        kill -USR1 `cat /run/nginx.pid`
    fi
endscript
```

## Best Practices

1. **Monitor disk space**: Set up alerts for log directory size
2. **Adjust retention**: Keep logs long enough for security analysis but not so long they fill disk
3. **Compress logs**: Always enable compression to save space
4. **Test rotation**: Test logrotate config before relying on it
5. **Backup logs**: Consider backing up rotated logs to archival storage
6. **Parse regularly**: Set up automated analysis of logs for security insights
7. **Document changes**: Note any customizations to rotation config

## Integration with Monitoring Systems

### Prometheus + Grafana

Create a log exporter to track:
- Number of IPs blacklisted per day
- Most frequently blocked IPs
- Most commonly blocked URIs

### Splunk

Configure Splunk forwarder to ship logs:
```
[monitor:///var/log/nginx/hijinx/hijinx.log]
sourcetype = hijinx
index = security
```

### CloudWatch (AWS)

Use CloudWatch Logs agent to ship to AWS for analysis

## Summary

- **Default**: Logs rotate daily, keep 30 days, compress old logs
- **File**: `/var/log/nginx/hijinx/hijinx.log`
- **Tool**: Use logrotate (standard on most systems)
- **Install**: `make logrotate` or manually copy config
- **Test**: `sudo logrotate -d /etc/logrotate.d/hijinx`
- **Customize**: Edit `/etc/logrotate.d/hijinx` as needed
