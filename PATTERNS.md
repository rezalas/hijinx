# Hijinx Patterns Guide

## Overview

Hijinx uses a configurable pattern file to detect suspicious requests. This allows you to customize what behavior is considered suspicious without recompiling the module.

## Configuration

### Enable Pattern-Based Detection

In your nginx configuration:

```nginx
http {
    hijinx on;
    hijinx_patterns /etc/nginx/hijinx/patterns.txt;
    hijinx_threshold 5;
    
    # ... rest of config
}
```

### Directive: `hijinx_patterns`

- **Syntax**: `hijinx_patterns path;`
- **Default**: `/etc/nginx/hijinx/patterns.txt`
- **Context**: `http`, `server`, `location`

Specifies the path to the patterns file.

## Pattern File Format

### Basic Rules

1. **One pattern per line**
2. **Case-sensitive** substring matching
3. **Comments**: Lines starting with `#` are ignored
4. **Empty lines**: Ignored
5. **Whitespace**: Leading and trailing whitespace is automatically trimmed
6. **Maximum**: 100 patterns per file

### Pattern Matching

Patterns are matched as **substrings** against the request URI.

**Example**:
- Pattern: `/admin`
- Matches: `/admin`, `/admin/`, `/admin/users`, `/secret/admin`, `/administration`
- Does NOT match: `/ADMIN` (case-sensitive)

## How It Works

```
Request → Pattern Match? → Yes → Status 403/404? → Yes → Increment Counter
            ↓                            ↓
           No                           No
            ↓                            ↓
         Allow                        Allow
```

1. **Pattern Check**: Each request URI is checked against all loaded patterns
2. **Status Check**: If a pattern matches, Hijinx waits for the response
3. **Counter Increment**: Only if status is 403 or 404, the IP counter increases
4. **Blacklist**: When counter reaches threshold, IP is blacklisted

**Important**: Matching a pattern alone does NOT block the request. The request must ALSO return 403 or 404.

## Default Patterns

If the patterns file doesn't exist, Hijinx loads these defaults:

- `/admin`
- `/login`
- `.php`

## Example Patterns

### Common Attack Vectors

```
# Admin interfaces
/admin
/administrator
/wp-admin
/phpmyadmin

# Backdoor attempts
shell
backdoor
c99.php
cmd.php

# Sensitive files
/.env
/.git
/.aws
/config

# WordPress (if not using WordPress)
/wp-login.php
/xmlrpc.php

# Old software
/joomla
/drupal
```

### Application-Specific

For a **Ruby on Rails** application:
```
/admin
/rails/admin
/admin/dashboard
/sidekiq
```

For a **Django** application:
```
/admin
/django-admin
/__debug__
```

For a **Node.js/Express** application:
```
/admin
/management
/admin/api
```

### File Type Protection

```
.php
.asp
.aspx
.jsp
.cgi
.sql
.bak
.old
.conf
```

### Directory Probing

```
/backup
/backups
/tmp
/temp
/uploads
/files
```

## Pattern Strategy

### Be Specific

**Too broad**:
```
/user    # Will match /users, /username, /api/user, etc.
```

**Better**:
```
/user/admin
/admin/users
```

### Consider Your Application

If your application legitimately uses certain paths, don't include them:

**Example**: Running a WordPress site?
```
# DON'T include these:
# /wp-admin  ← your legitimate admin panel
# /wp-login  ← your legitimate login

# DO include these if you're NOT using WordPress:
/wp-admin
/wp-login
```

### Test Before Deploying

1. Add pattern to test file
2. Make legitimate requests to your site
3. Check if any false positives occur
4. Adjust pattern specificity

## Managing Patterns

### Adding Patterns

1. Edit the patterns file:
```bash
sudo nano /etc/nginx/hijinx/patterns.txt
```

2. Add your pattern:
```
# Custom API protection
/api/internal
/api/v2/admin
```

3. Reload nginx:
```bash
sudo nginx -s reload
```

### Removing Patterns

1. Comment out or delete the line:
```
# /admin  ← now disabled
```

2. Reload nginx:
```bash
sudo nginx -s reload
```

### Testing Patterns

Test pattern matching without actually blocking:

```bash
# Make a request that should match
curl http://localhost/admin

# Check nginx error log for hijinx messages
tail -f /var/log/nginx/error.log | grep hijinx

# Check hijinx log
tail -f /var/log/nginx/hijinx/hijinx.log
```

## Multiple Pattern Files

You can use different pattern files for different locations:

```nginx
http {
    hijinx on;
    hijinx_patterns /etc/nginx/hijinx/patterns-default.txt;
    
    server {
        server_name api.example.com;
        
        # Use API-specific patterns
        hijinx_patterns /etc/nginx/hijinx/patterns-api.txt;
    }
    
    server {
        server_name cms.example.com;
        
        # Use CMS-specific patterns
        hijinx_patterns /etc/nginx/hijinx/patterns-cms.txt;
    }
}
```

## Pattern File Examples

### Minimal (Low False Positives)
```
# Only obvious attack attempts
/admin
/.env
/.git
shell
backdoor
```

### Moderate (Balanced)
```
# Admin paths
/admin
/administrator
/wp-admin

# Sensitive files
/.env
/.git
/config

# PHP probing (if not using PHP)
.php

# Backdoors
shell
backdoor
```

### Aggressive (Maximum Protection)
```
# Everything in the default patterns.txt file
# Plus application-specific paths
# Plus file extensions
# Plus known vulnerability paths
```

## Troubleshooting

### Pattern not matching

**Check pattern syntax**:
```bash
# View loaded patterns
grep -v "^#" /etc/nginx/hijinx/patterns.txt | grep -v "^$"
```

**Verify pattern is exact substring**:
- Pattern: `/admin`
- URI: `/Admin` ← Won't match (case-sensitive)
- URI: `/admin/` ← Will match

### Too many false positives

**Check logs**:
```bash
tail -f /var/log/nginx/hijinx/hijinx.log
```

**Solution**: Make patterns more specific
- Change `/user` to `/user/admin`
- Change `/api` to `/api/admin`

### Pattern file not loading

**Check file exists**:
```bash
ls -la /etc/nginx/hijinx/patterns.txt
```

**Check permissions**:
```bash
sudo chmod 644 /etc/nginx/hijinx/patterns.txt
sudo chown nginx:nginx /etc/nginx/hijinx/patterns.txt
```

**Check nginx logs**:
```bash
tail -f /var/log/nginx/error.log | grep hijinx
```

If file doesn't exist, Hijinx will use defaults (`/admin`, `/login`, `.php`).

## Best Practices

1. **Start Conservative**: Begin with minimal patterns and add more as needed
2. **Monitor Logs**: Watch what's being caught before increasing threshold
3. **Test Thoroughly**: Test patterns on staging before production
4. **Document Changes**: Comment your custom patterns in the file
5. **Regular Review**: Periodically review and update patterns
6. **Backup**: Keep a backup of your patterns file
7. **Version Control**: Consider keeping patterns file in version control

## Performance Considerations

- **Pattern Count**: Each pattern is checked for every suspicious request
- **Pattern Length**: Longer patterns take slightly more time to match
- **Recommendation**: Keep patterns under 50 for optimal performance
- **Impact**: Minimal - pattern matching is very fast (microseconds)

## Security Notes

- Patterns are **substrings**, not regex (for security and performance)
- No regex means no ReDoS (Regular Expression Denial of Service) vulnerability
- Patterns cannot execute code
- Maximum 100 patterns enforced to prevent resource exhaustion

## Examples by Framework

### WordPress
```
/wp-admin
/wp-login.php
/xmlrpc.php
/wp-includes
/wp-content/plugins
```

### Laravel
```
/admin
/horizon
/telescope
/.env
/storage
```

### Django
```
/admin
/django-admin
/__debug__
/.env
/media
```

### Ruby on Rails
```
/admin
/rails/admin
/sidekiq
/.env
/active_storage
```

### ASP.NET
```
/admin
/umbraco
/sitecore
/web.config
```

## Summary

- **Format**: One pattern per line, substring matching
- **Location**: Configure with `hijinx_patterns` directive
- **Default**: `/etc/nginx/hijinx/patterns.txt`
- **Reload**: `sudo nginx -s reload` after changes
- **Matching**: Case-sensitive substring search
- **Effect**: Only increments counter if request returns 403/404

Pattern-based detection makes Hijinx flexible and adaptable to your specific application needs without requiring module recompilation.
