# Configurable Patterns Feature

## Overview

The Hijinx module supports **configurable pattern files** for flexible suspicious pattern detection.

### Implementation
Patterns are loaded from a text file:
- Default: `/etc/nginx/hijinx/patterns.txt`
- Configurable per location
- Easy to customize

To change patterns:
1. Edit patterns file
2. Reload nginx

## Configuration

### New Directive: `hijinx_patterns`

```nginx
http {
    hijinx on;
    hijinx_patterns /etc/nginx/hijinx/patterns.txt;
    hijinx_threshold 5;
}
```

### Different Patterns Per Location

```nginx
server {
    server_name api.example.com;
    hijinx_patterns /etc/nginx/hijinx/patterns-api.txt;
}

server {
    server_name cms.example.com;
    hijinx_patterns /etc/nginx/hijinx/patterns-cms.txt;
}
```

## Pattern File Format

Simple text file format:
```
# Comments start with #
# One pattern per line
# Blank lines ignored

/admin
/login
.php
/wp-admin
/.env
```

Patterns are matched as **substrings** (not regex):
- Pattern `/admin` matches `/admin`, `/administrator`, `/secret/admin`
- Pattern `.php` matches `/test.php`, `/index.php`, `/path/file.php`

## Key Features

- **Easy to customize** - Edit text file, no recompilation  
- **Hot reload** - Changes apply with `nginx -s reload`  
- **Well documented** - Extensive comments in default file  
- **Location-specific** - Different patterns per server/location  
- **Safe defaults** - Falls back to defaults if file missing  
- **Maximum 100 patterns** - Prevents resource exhaustion  
- **No regex** - No ReDoS vulnerabilities  
- **Performance** - Pattern matching is very fast  

## Default Patterns Included

The default `patterns.txt` includes:

- **Admin paths**: `/admin`, `/administrator`, `/wp-admin`
- **PHP probing**: `.php` (for non-PHP servers)
- **Sensitive files**: `/.env`, `/.git`, `/.aws`
- **WordPress**: `/wp-login`, `/xmlrpc.php`
- **Database tools**: `/phpmyadmin`, `/adminer`
- **Backdoors**: `shell`, `backdoor`, `c99.php`
- **Old software**: `/joomla`, `/drupal`, `/magento`
- **API abuse**: `/api/admin`, `/api/v1/admin`
- **Development**: `/debug`, `/test`, `/.svn`

Plus many more with extensive documentation and examples.

## Installation

The patterns file is automatically installed by `make setup` or `make install`.

Manual installation:
```bash
sudo cp patterns.txt /etc/nginx/hijinx/patterns.txt
sudo chmod 644 /etc/nginx/hijinx/patterns.txt
sudo chown nginx:nginx /etc/nginx/hijinx/patterns.txt
```

## Usage Examples

### Add Custom Pattern

```bash
echo "/my-secret-admin" >> /etc/nginx/hijinx/patterns.txt
sudo nginx -s reload
```

### Temporary Disable Pattern

```bash
# Edit file and comment out the pattern
# /admin  ← disabled
sudo nginx -s reload
```

### Test Pattern Matching

```bash
# Make a request that should match
curl http://localhost/admin

# Check logs
tail -f /var/log/nginx/hijinx/hijinx.log
```

## Technical Implementation

### Module Components

1. **Structures**:
   - `ngx_http_hijinx_pattern_t` - Pattern storage
   - `patterns` array in config structure

2. **Configuration directive**:
   - `hijinx_patterns` - Path to patterns file

3. **Functions**:
   - `ngx_http_hijinx_load_patterns()` - Load patterns from file
   - `ngx_http_hijinx_check_patterns()` - Check URI against patterns

### Pattern Matching

Patterns are checked using efficient substring matching.

### Backward Compatibility

If patterns file doesn't exist, module loads default patterns:
- `/admin`
- `/login`
- `.php`

## Setup

1. **Install patterns file**:
   ```bash
   make setup
   ```

2. **Configure nginx**:
   ```nginx
   hijinx_patterns /etc/nginx/hijinx/patterns.txt;
   ```

3. **Reload nginx**:
   ```bash
   sudo nginx -s reload
   ```

4. **Customize patterns**:
   ```bash
   sudo nano /etc/nginx/hijinx/patterns.txt
   sudo nginx -s reload
   ```

## Testing

Test the patterns system:

```bash
# View loaded patterns
grep -v "^#" /etc/nginx/hijinx/patterns.txt | grep -v "^$"

# Test a pattern match
curl http://localhost/admin
curl http://localhost/test.php

# Check if IP is being tracked
tail -f /var/log/nginx/error.log | grep hijinx

# Reach threshold and check blacklist
for i in {1..6}; do curl http://localhost/admin; done
cat /etc/nginx/hijinx/blacklist.txt
```

## Documentation

Complete documentation available in:

- **[PATTERNS.md](PATTERNS.md)** - Full pattern system guide
  - Pattern file format
  - Matching behavior
  - Examples by framework
  - Best practices
  - Troubleshooting

- **[patterns.txt](patterns.txt)** - Default patterns file
  - Extensive inline documentation
  - Format rules
  - Pattern examples
  - Custom pattern section

- **[README.md](README.md)** - Updated with patterns directive
- **[config_template.conf](config_template.conf)** - Example configuration

## Benefits

1. **Flexibility**: Customize patterns without recompiling
2. **Maintainability**: Easy to add/remove patterns
3. **Application-specific**: Different patterns per app/location
4. **No downtime**: Changes apply with reload (not restart)
5. **Documentation**: Patterns file is self-documenting
6. **Version control**: Track pattern changes in git
7. **Testing**: Easy to test new patterns

## Performance

- **Pattern loading**: Happens once at nginx start/reload
- **Pattern matching**: Very fast (microseconds per request)
- **Memory usage**: Minimal (~100 bytes per pattern)
- **Recommended**: Keep patterns under 50 for optimal performance
- **Maximum**: 100 patterns enforced

## Security Notes

- Patterns are substrings, not regex (no ReDoS vulnerability)
- Maximum 100 patterns prevents resource exhaustion
- Patterns cannot execute code
- File is read-only after loading (no runtime modification)
- Safe defaults ensure basic protection even without file

## Next Steps

1. Review default patterns in `patterns.txt`
2. Customize for your application
3. Test with your traffic patterns
4. Monitor logs to tune patterns
5. Document your custom patterns

## Support

For questions or issues:
- Read [PATTERNS.md](PATTERNS.md) for detailed documentation
- Check [README.md](README.md) for configuration examples
- Review logs: `/var/log/nginx/error.log` and `/var/log/nginx/hijinx/hijinx.log`

---

**Key Takeaway**: Pattern files make Hijinx flexible and adaptable to any application without module recompilation.
