# Hijinx HTML Content for Random Serving

This directory contains HTML files that are randomly served to suspicious requests when `hijinx_serve_random_content` is enabled.

## Included Files

- **admin-login.html** - Generic modern admin login page
- **wordpress-admin.html** - Realistic WordPress admin login
- **phpmyadmin.html** - phpMyAdmin database interface  
- **server-status.html** - Server monitoring dashboard

## Purpose

These files serve as decoys to:
- Waste attackers' time analyzing fake content
- Hide your actual site structure
- Make profiling your site more difficult
- Appear as legitimate admin interfaces

## Adding Your Own

1. Create an HTML file in this directory
2. Must have `.html` extension
3. Keep files under 100KB
4. Use inline CSS/JS for self-contained files
5. Reload nginx to load new files

## Example

```html
<!DOCTYPE html>
<html>
<head>
    <title>Control Panel</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        .login { max-width: 400px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="login">
        <h2>System Login</h2>
        <form action="/login" method="post">
            <input type="text" name="user" placeholder="Username">
            <input type="password" name="pass" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
```

Save as `custom-login.html` in this directory, then:

```bash
sudo nginx -s reload
```

## Notes

- Maximum 50 HTML files
- Files are loaded into memory at nginx startup
- Random selection based on time + connection number
- Returns 200 OK with HTML content
- Suspicious requests never reach your application

See [RANDOM_CONTENT.md](../RANDOM_CONTENT.md) for full documentation.
