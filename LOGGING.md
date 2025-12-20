# Hijinx Logging Guide

## Overview

Hijinx maintains two separate log files to track different types of events:

- **hijinx.log** - Activity log for all security events
- **hijinx-error.log** - Error log for module issues

Both logs are located in `/var/log/nginx/hijinx/` by default (configurable with `hijinx_log_dir`).

## Log Files

### hijinx.log - Activity Log

Records all security-related events:

**Blacklisting Events**
```
2025-12-18 10:15:23 - 192.168.1.100 - Added to blacklist thanks to final straw - /admin
```

**Random Content Serving** (when `hijinx_serve_random_content` is enabled)
```
2025-12-18 10:22:45 - 10.0.0.50 - Served random content (file #2) - /wp-login.php | GET /wp-login.php HTTP/1.1 200
```

**Format**:
```
TIMESTAMP - IP_ADDRESS - EVENT_TYPE - REQUEST_URI | METHOD URI PROTOCOL STATUS
```

### hijinx-error.log - Error Log

Records module errors and issues:

### nginx error.log - Debug Logging

When `hijinx_debug on;` is enabled in the nginx configuration, detailed diagnostic information is logged to nginx's main error.log at WARN level:

**Debug Events Include:**
- Handler entry and URI being processed
- IP address extraction and blacklist checks
- Pattern matching details
- IP counter increments and threshold checks
- Fake content serving decisions

**Example debug output:**
```
2025-12-18 10:15:23 [warn] hijinx: Handler entered for URI=/admin
2025-12-18 10:15:23 [warn] hijinx: Got IP=192.168.1.100, checking blacklist
2025-12-18 10:15:23 [warn] hijinx: Pattern check for /admin: is_suspicious=1
2025-12-18 10:15:23 [warn] hijinx: IP 192.168.1.100 count is now 3 (threshold=5)
```

**Note:** Debug logging should only be enabled for troubleshooting as it significantly increases log volume. Disable in production for optimal performance.

**Common Errors**:
```
2025-12-18 10:30:00 - ERROR - No HTML files loaded for random content serving
2025-12-18 10:45:12 - ERROR - Failed to allocate buffer for random content
2025-12-18 11:00:00 - ERROR - Failed to open hijinx.log for random content logging
```

**Format**:
```
TIMESTAMP - ERROR - MESSAGE
```

## Log Entry Details

### Blacklisting Event

When an IP is blacklisted:
- **Timestamp**: Date and time of blacklisting
- **IP Address**: The blocked IP
- **Message**: "Added to blacklist thanks to final straw"
- **URI**: The request that triggered the final threshold

### Random Content Event

When fake HTML is served:
- **Timestamp**: Date and time of serving
- **IP Address**: Who requested
- **File Index**: Which HTML file was served (0-based index)
- **URI**: What path was requested
- **Original Request**: The complete request line in access.log format (METHOD URI PROTOCOL STATUS)

Example: `file #2` means the 3rd HTML file (0-indexed) was served

The log entry includes both what was served and the original request details, allowing you to correlate the fake response with the actual request made.

### Error Event

When an error occurs:
- **Timestamp**: Date and time of error
- **Type**: Always "ERROR"
- **Message**: Description of the problem

## Monitoring

### Real-Time Monitoring

**Watch all activity:**
```bash
tail -f /var/log/nginx/hijinx/hijinx.log
```

**Watch only blacklisting:**
```bash
tail -f /var/log/nginx/hijinx/hijinx.log | grep "Added to blacklist"
```

**Watch only random content:**
```bash
tail -f /var/log/nginx/hijinx/hijinx.log | grep "Served random content"
```

**Watch errors:**
```bash
tail -f /var/log/nginx/hijinx/hijinx-error.log
```

### Log Analysis

**Count blacklisted IPs:**
```bash
grep "Added to blacklist" /var/log/nginx/hijinx/hijinx.log | wc -l
```

**List unique blacklisted IPs:**
```bash
grep "Added to blacklist" /var/log/nginx/hijinx/hijinx.log | \
  awk '{print $4}' | sort -u
```

**Most targeted paths:**
```bash
grep -E "(Added to blacklist|Served random content)" /var/log/nginx/hijinx/hijinx.log | \
  awk -F' - ' '{print $NF}' | sort | uniq -c | sort -rn | head -20
```

**Random content file usage:**
```bash
grep "Served random content" /var/log/nginx/hijinx/hijinx.log | \
  sed 's/.*file #\([0-9]*\).*/\1/' | sort | uniq -c | sort -rn
```

**Most active attacking IPs:**
```bash
grep "Served random content" /var/log/nginx/hijinx/hijinx.log | \
  awk '{print $4}' | sort | uniq -c | sort -rn | head -20
```

**Hourly activity:**
```bash
grep -E "(Added to blacklist|Served random content)" /var/log/nginx/hijinx/hijinx.log | \
  awk '{print $2}' | cut -d: -f1 | sort | uniq -c
```

**Daily activity:**
```bash
grep -E "(Added to blacklist|Served random content)" /var/log/nginx/hijinx/hijinx.log | \
  awk '{print $1}' | sort | uniq -c
```

## Log Rotation

Both log files are automatically rotated using logrotate:

**Configuration:** `/etc/logrotate.d/hijinx`

**Default settings:**
- Rotate daily
- Keep 30 days
- Compress old logs
- Auto-signal nginx

**Install logrotate:**
```bash
make logrotate
# or
sudo cp logrotate-hijinx.conf /etc/logrotate.d/hijinx
```

See [LOG_ROTATION.md](LOG_ROTATION.md) for detailed information.

## Integration with Monitoring Tools

### Grafana / Prometheus

Parse logs with promtail or filebeat:

```yaml
# promtail config
scrape_configs:
  - job_name: hijinx
    static_configs:
      - targets:
          - localhost
        labels:
          job: hijinx
          __path__: /var/log/nginx/hijinx/*.log
```

### ELK Stack

Logstash grok pattern:

```
%{TIMESTAMP_ISO8601:timestamp} - %{IP:ip} - %{DATA:event_type} - %{GREEDYDATA:uri}
```

### Splunk

```
[monitor:///var/log/nginx/hijinx/]
disabled = false
sourcetype = hijinx_log
index = security
```

### Simple Monitoring Script

```bash
#!/bin/bash
# Simple hijinx monitor

LOG_FILE="/var/log/nginx/hijinx/hijinx.log"
ALERT_THRESHOLD=10

# Count events in last hour
RECENT_EVENTS=$(grep -c "$(date +%Y-%m-%d\ %H)" "$LOG_FILE")

if [ "$RECENT_EVENTS" -gt "$ALERT_THRESHOLD" ]; then
    echo "Alert: $RECENT_EVENTS hijinx events in the last hour"
    # Send alert (email, slack, etc)
fi
```

## Log Format Specifications

### Activity Log Format

```
<TIMESTAMP> - <IP> - <EVENT> - <URI>
```

**Fields:**
- `TIMESTAMP`: YYYY-MM-DD HH:MM:SS format
- `IP`: IPv4 or IPv6 address
- `EVENT`: Either "Added to blacklist..." or "Served random content..."
- `URI`: The request URI

**Parsing:**
- Split by " - " (space-dash-space)
- Field 0: Timestamp
- Field 1: IP
- Field 2: Event description
- Field 3: URI

### Error Log Format

```
<TIMESTAMP> - ERROR - <MESSAGE>
```

**Fields:**
- `TIMESTAMP`: YYYY-MM-DD HH:MM:SS format
- `TYPE`: Always "ERROR"
- `MESSAGE`: Error description

## Troubleshooting

### Logs not being written

**Check permissions:**
```bash
ls -la /var/log/nginx/hijinx/
```

Should be writable by nginx user (nginx or www-data).

**Fix permissions:**
```bash
sudo chown -R nginx:nginx /var/log/nginx/hijinx
# or
sudo chown -R www-data:www-data /var/log/nginx/hijinx
```

### Log directory doesn't exist

**Create it:**
```bash
sudo mkdir -p /var/log/nginx/hijinx
sudo chown nginx:nginx /var/log/nginx/hijinx
```

Or run:
```bash
make setup
```

### Logs growing too large

**Check current size:**
```bash
du -sh /var/log/nginx/hijinx/
```

**Ensure logrotate is working:**
```bash
sudo logrotate -d /etc/logrotate.d/hijinx
```

**Force rotation:**
```bash
sudo logrotate -f /etc/logrotate.d/hijinx
```

### Missing log entries

**Check nginx error log:**
```bash
sudo tail /var/log/nginx/error.log | grep hijinx
```

**Verify module is loaded:**
```bash
nginx -V 2>&1 | grep hijinx
```

**Check configuration:**
```bash
nginx -T | grep hijinx
```

## Security Considerations

### Log Retention

- Activity logs may contain sensitive information (IPs, URIs)
- Follow your organization's data retention policies
- Consider privacy regulations (GDPR, CCPA, etc.)

### Log Access

Restrict access to log files:

```bash
sudo chmod 640 /var/log/nginx/hijinx/*.log
sudo chown nginx:adm /var/log/nginx/hijinx/*.log
```

### Log Anonymization

To anonymize IPs in logs, modify the logging functions in the module source, or use a log processor:

```bash
# Example: hash IPs in logs
sed 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/REDACTED/g' hijinx.log
```

## Performance Impact

### Write Performance

- Logs use append-only writes (fast)
- No buffering (immediate write)
- Minimal I/O impact
- Each event: ~150 bytes

### Disk Usage

**Typical usage:**
- 100 events/day = ~15KB/day
- 1000 events/day = ~150KB/day
- With compression: ~10:1 ratio
- 30 days: ~450KB compressed (1000 events/day)

**High-traffic site:**
- 10,000 events/day = ~1.5MB/day
- 30 days: ~4.5MB compressed

## Best Practices

1. **Monitor both logs**: Check activity and error logs regularly
2. **Set up alerts**: Notify on unusual activity patterns
3. **Analyze trends**: Look for patterns in attacks
4. **Rotate regularly**: Use logrotate to manage disk usage
5. **Backup important logs**: Keep historical data for forensics
6. **Integrate with SIEM**: Feed logs to security monitoring tools
7. **Review errors**: Check error log for module issues
8. **Archive old logs**: Move old logs to cold storage

## Example Dashboards

### Daily Summary

```bash
#!/bin/bash
LOG="/var/log/nginx/hijinx/hijinx.log"
TODAY=$(date +%Y-%m-%d)

echo "Hijinx Activity Summary - $TODAY"
echo "=================================="
echo ""
echo "Blacklisted IPs: $(grep "$TODAY" "$LOG" | grep -c "Added to blacklist")"
echo "Random Content Served: $(grep "$TODAY" "$LOG" | grep -c "Served random content")"
echo ""
echo "Top 5 Attacked Paths:"
grep "$TODAY" "$LOG" | awk -F' - ' '{print $NF}' | sort | uniq -c | sort -rn | head -5
echo ""
echo "Top 5 Attacking IPs:"
grep "$TODAY" "$LOG" | awk '{print $4}' | sort | uniq -c | sort -rn | head -5
```

### Weekly Report

```bash
#!/bin/bash
LOG="/var/log/nginx/hijinx/hijinx.log"
LAST_WEEK=$(date -d '7 days ago' +%Y-%m-%d)

echo "Hijinx Weekly Report"
echo "===================="
echo "From: $LAST_WEEK"
echo "To: $(date +%Y-%m-%d)"
echo ""

BLACKLISTED=$(grep -c "Added to blacklist" "$LOG")
RANDOM=$(grep -c "Served random content" "$LOG")

echo "Total Blacklisted: $BLACKLISTED"
echo "Total Random Content: $RANDOM"
echo "Total Events: $((BLACKLISTED + RANDOM))"
echo ""
echo "Average per day: $(( (BLACKLISTED + RANDOM) / 7 ))"
```

## Summary

Hijinx provides comprehensive logging of all security events:

- **hijinx.log**: All security activity (blacklisting, random content)
- **hijinx-error.log**: Module errors and issues
- **Standard format**: Easy to parse and analyze
- **Rotation ready**: Works with logrotate out of the box
- **Integration friendly**: Compatible with all major monitoring tools

Monitor both logs regularly to maintain security awareness and catch any module issues early.
