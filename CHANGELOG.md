# Hijinx Module Changelog

## Log Rotation Implementation

The Hijinx module uses standard log rotation practices with logrotate.

### Log System Features
- Single log file: `hijinx.log`
- All events append to same file
- Rotated by standard tools (logrotate)
- Compatible with existing log management infrastructure

## Technical Details

### ngx_http_hijinx_module.c
**Function**: `ngx_http_hijinx_log_event()`

**Implementation**:
- Writes to single file: `hijinx.log`
- Uses `NGX_FILE_CREATE_OR_OPEN` mode
- Simplified file path construction

**Code**:
```c
len = ngx_snprintf(logpath, sizeof(logpath), "%V/hijinx.log",
                  &hlcf->log_dir) - logpath;
```

### logrotate-hijinx.conf
Logrotate configuration with:
- Daily rotation schedule
- 30-day retention
- Compression enabled
- Automatic nginx signal (USR1) to reopen logs
- Proper permissions (0640 nginx:nginx)

### Makefile
Build automation includes:
- `install` target includes logrotate installation
- `logrotate` target for standalone installation
- Color-coded output and help text

## Benefits

1. **Standard Practice**: Uses industry-standard log rotation
2. **Better Management**: Single file easier to monitor and analyze
3. **Tool Compatibility**: Works with logrotate, logwatch, ELK, etc.
4. **Disk Space**: Automatic compression and retention management
5. **Flexibility**: Easy to customize rotation frequency and retention
6. **Reliability**: Proven log rotation mechanism used system-wide

## Installation

1. **Install logrotate config**:
   ```bash
   make logrotate
   ```

2. **Reload nginx**:
   ```bash
   sudo nginx -s reload
   ```

4. **Clean up old logs** (optional):
   ```bash
   # Archive old timestamped logs
   cd /var/log/nginx/hijinx
   tar -czf old-logs-$(date +%Y%m%d).tar.gz hijinx_*.log
   rm hijinx_*.log
   ```

## Testing the New Setup

1. **Verify log file creation**:
   ```bash
   ls -la /var/log/nginx/hijinx/hijinx.log
   ```

2. **Trigger a log entry**:
   ```bash
   # Make suspicious requests to trigger blacklist
   for i in {1..6}; do curl http://localhost/admin; done
   ```

3. **Check the log**:
   ```bash
   tail /var/log/nginx/hijinx/hijinx.log
   ```

4. **Test logrotate**:
   ```bash
   # Dry run
   sudo logrotate -d /etc/logrotate.d/hijinx
   
   # Force rotation
   sudo logrotate -f /etc/logrotate.d/hijinx
   ```

5. **Verify rotation worked**:
   ```bash
   ls -la /var/log/nginx/hijinx/
   # Should see: hijinx.log and hijinx.log-YYYYMMDD.gz
   ```

## Configuration Options

### Change Rotation Frequency

Edit `/etc/logrotate.d/hijinx`:

```
# Daily (default)
daily

# Or weekly
weekly

# Or monthly
monthly
```

### Change Retention Period

```
# Keep 30 days (default)
rotate 30

# Keep 90 days
rotate 90

# Keep 1 year
rotate 365
```

### Disable Compression

```
# Remove or comment out:
# compress
# delaycompress
```

## Quick Reference

| Aspect | Value |
|--------|-------|
| Log file | `/var/log/nginx/hijinx/hijinx.log` |
| Logrotate config | `/etc/logrotate.d/hijinx` |
| Default frequency | Daily |
| Default retention | 30 days |
| Compression | Yes (gzip) |
| Install command | `make logrotate` |
| Test command | `sudo logrotate -d /etc/logrotate.d/hijinx` |

## Support

See the following documentation:
- **LOG_ROTATION.md**: Complete guide to log rotation
- **README.md**: Updated monitoring section
- **INSTALL.md**: Installation with logrotate setup

## Rollback

If you need to revert to timestamped logs (not recommended):

1. Restore old `ngx_http_hijinx_module.c` from version control
2. Rebuild: `make build && make install`
3. Remove logrotate config: `sudo rm /etc/logrotate.d/hijinx`
4. Reload nginx: `sudo nginx -s reload`

However, standard rotation is strongly recommended for production use.
