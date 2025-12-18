# Hijinx Log Flow Diagram

## Log Rotation Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Nginx Request Flow                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│           Hijinx Module (ngx_http_hijinx_module)                │
│                                                                  │
│  1. Access Phase: Check blacklist + detect patterns             │
│  2. Log Phase: Check status code (403/404)                      │
│  3. Increment IP counter in shared memory                       │
│  4. If threshold reached → Add to blacklist                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    When IP is blacklisted
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                 ngx_http_hijinx_log_event()                     │
│                                                                  │
│  • Opens: /var/log/nginx/hijinx/hijinx.log                     │
│  • Appends: "YYYY-MM-DD HH:MM:SS - IP - Message - URI"         │
│  • Closes file                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       hijinx.log                                │
│                                                                  │
│  2025-12-18 10:15:23 - 192.168.1.100 - Added to blacklist...   │
│  2025-12-18 10:22:45 - 10.0.0.50 - Added to blacklist...       │
│  2025-12-18 11:05:12 - 172.16.0.25 - Added to blacklist...     │
│  ... (grows continuously)                                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    Daily at configured time
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Logrotate                                │
│              (/etc/logrotate.d/hijinx)                          │
│                                                                  │
│  1. Rename: hijinx.log → hijinx.log-20251218                   │
│  2. Create: new empty hijinx.log                               │
│  3. Signal: nginx (kill -USR1) to reopen logs                  │
│  4. Compress: hijinx.log-20251218 → .gz                        │
│  5. Delete: logs older than 30 days                            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Rotated Log Archive                           │
│                                                                  │
│  hijinx.log              ← Current (active)                     │
│  hijinx.log-20251218     ← Yesterday (uncompressed)            │
│  hijinx.log-20251217.gz  ← 2 days ago                          │
│  hijinx.log-20251216.gz  ← 3 days ago                          │
│  ...                                                            │
│  hijinx.log-20251118.gz  ← 30 days ago (will be deleted)      │
└─────────────────────────────────────────────────────────────────┘
```

## Log Lifecycle

```
Day 1:  hijinx.log (active, 0-5MB)
           ↓ 11:59 PM
Day 2:  hijinx.log (active, 0MB - new)
        hijinx.log-20251218 (archived, 5MB)
           ↓ 11:59 PM
Day 3:  hijinx.log (active, 0MB - new)
        hijinx.log-20251219 (archived, 3MB)
        hijinx.log-20251218.gz (compressed, 500KB)
           ↓
        ... continues daily ...
           ↓
Day 31: hijinx.log (active)
        hijinx.log-YYYYMMDD (last 30 days compressed)
        [Logs from Day 1 deleted]
```

## File Operations Timeline

```
Time    Event                          Files
──────  ─────────────────────────     ─────────────────────────
10:00   IP blocked, log entry          hijinx.log (5MB)

14:00   IP blocked, log entry          hijinx.log (5.1MB)

18:00   IP blocked, log entry          hijinx.log (5.2MB)

23:59   Logrotate runs                 hijinx.log (5.2MB)
        ↓
00:00   After rotation:
        - hijinx.log                   (0KB - new file)
        - hijinx.log-20251218          (5.2MB - renamed)

00:01   Compression runs               
        - hijinx.log                   (0KB)
        - hijinx.log-20251218.gz       (600KB - compressed)

00:02   Nginx reopens log file         (nginx continues writing)
```

## Integration Points

```
┌──────────────┐    read     ┌──────────────┐
│ Monitoring   │◄────────────│  hijinx.log  │
│ Tools        │             └──────────────┘
└──────────────┘                     │
      │                              │
      │                              │ rotate
      ▼                              ▼
┌──────────────┐             ┌──────────────┐
│  - Grafana   │             │  Logrotate   │
│  - ELK       │             │              │
│  - Splunk    │             │  - Compress  │
│  - Logwatch  │             │  - Archive   │
└──────────────┘             │  - Delete    │
                             └──────────────┘
                                     │
                                     │ archive
                                     ▼
                             ┌──────────────┐
                             │ Compressed   │
                             │ Archives     │
                             │ (.gz files)  │
                             └──────────────┘
```

## Log System Structure

```
/var/log/nginx/hijinx/
├── hijinx.log                     (5.2MB - current)
├── hijinx.log-20251218           (5.1MB - yesterday)
├── hijinx.log-20251217.gz        (600KB - 2 days ago)
├── hijinx.log-20251216.gz        (580KB - 3 days ago)
└── ... (30 compressed archives)

Benefits:
- Single active file
- Easy to monitor: tail -f hijinx.log
- Automatic rotation
- Compressed archives
- Easy to search and parse
- Standard log management
```

## Disk Space Calculation

### Assumptions
- 100 IPs blacklisted per day
- 150 bytes per log entry
- 30-day retention
- 10:1 compression ratio

### Math
```
Per day:    100 entries × 150 bytes = 15,000 bytes = ~15KB
Compressed: 15KB ÷ 10 = 1.5KB
30 days:    (15KB current) + (29 × 1.5KB compressed) = 58.5KB total

Even with 1000 blocks/day:
30 days:    (150KB current) + (29 × 15KB compressed) = 585KB total
```

### Conclusion
Disk space usage is minimal even with high blocking rates.

## Monitoring Commands Quick Reference

```bash
# Watch live
tail -f /var/log/nginx/hijinx/hijinx.log

# Count today's blocks
grep "$(date +%Y-%m-%d)" hijinx.log | wc -l

# Search all logs (including compressed)
zgrep "192.168.1.100" hijinx.log*

# Top 10 blocked IPs (all logs)
zcat -f hijinx.log* | grep -o '[0-9.]\{7,15\}' | sort | uniq -c | sort -rn | head

# Disk usage
du -sh /var/log/nginx/hijinx/

# Test rotation
sudo logrotate -d /etc/logrotate.d/hijinx

# Force rotation
sudo logrotate -f /etc/logrotate.d/hijinx
```

## System Flow Summary

1. **Module writes** → Single log file (`hijinx.log`)
2. **Logrotate runs** → Daily rotation
3. **File renamed** → `hijinx.log-YYYYMMDD`
4. **Nginx signaled** → Reopens log file (USR1)
5. **File compressed** → `.gz` extension added
6. **Old deleted** → After 30 days
7. **Cycle repeats** → Every day

This provides a reliable, maintainable, and industry-standard logging solution.
