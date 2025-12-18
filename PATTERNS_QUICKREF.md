# Hijinx Patterns - Quick Reference

## Files
| File | Purpose | Location |
|------|---------|----------|
| patterns.txt | Default patterns | /etc/nginx/hijinx/patterns.txt |
| PATTERNS.md | Full documentation | Documentation |
| PATTERNS_UPDATE.md | Feature summary | Documentation |

## Configuration Directive

```nginx
hijinx_patterns /etc/nginx/hijinx/patterns.txt;
```

## Pattern File Format

```
# Comment lines start with #
# One pattern per line
# Blank lines ignored
# Maximum 100 patterns

/admin
/login
.php
```

## Common Tasks

### Add Pattern
```bash
echo "/my-path" >> /etc/nginx/hijinx/patterns.txt
sudo nginx -s reload
```

### Disable Pattern
```bash
# Edit file and add # before pattern
# /admin  ← disabled
sudo nginx -s reload
```

### View Active Patterns
```bash
grep -v "^#" /etc/nginx/hijinx/patterns.txt | grep -v "^$"
```

### Test Pattern
```bash
# Make matching request
curl http://localhost/admin

# Check logs
tail -f /var/log/nginx/hijinx/hijinx.log
```

## Pattern Matching

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `/admin` | /admin, /administrator, /api/admin | /ADMIN (case-sensitive) |
| `.php` | /test.php, /index.php | .PHP, /php |
| `/wp-` | /wp-admin, /wp-login, /wp-content | /wordpress |

## Default Patterns Categories

- Admin paths: `/admin`, `/administrator`, `/wp-admin`
- PHP files: `.php`
- Sensitive: `/.env`, `/.git`, `/.aws`
- WordPress: `/wp-login`, `/xmlrpc.php`
- Backdoors: `shell`, `backdoor`, `c99.php`
- Databases: `/phpmyadmin`, `/adminer`

See `patterns.txt` for complete list with documentation.

## Per-Location Patterns

```nginx
http {
    hijinx_patterns /etc/nginx/hijinx/patterns-default.txt;
    
    server {
        server_name api.example.com;
        hijinx_patterns /etc/nginx/hijinx/patterns-api.txt;
    }
}
```

## Key Points

- Substring matching (not regex)  
- Case-sensitive  
- Max 100 patterns  
- Hot reload with nginx -s reload  
- Falls back to defaults if file missing  
- No ReDoS vulnerabilities  
- Very fast (microseconds)  

## Documentation

- Full guide: [PATTERNS.md](PATTERNS.md)
- Feature summary: [PATTERNS_UPDATE.md](PATTERNS_UPDATE.md)
- Configuration: [README.md](README.md)
