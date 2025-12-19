#!/bin/bash
# Monitor nginx hijinx module health

echo "=== Nginx Hijinx Module Health Check ==="
echo "Time: $(date)"
echo ""

# Check if nginx is running
if systemctl is-active --quiet nginx; then
    echo "✓ Nginx service: RUNNING"
else
    echo "✗ Nginx service: NOT RUNNING"
    exit 1
fi

# Check worker process stability
WORKER_COUNT=$(ps aux | grep "nginx: worker" | grep -v grep | wc -l)
echo "✓ Worker processes: $WORKER_COUNT active"

# Check for recent crashes (last 5 minutes)
RECENT_CRASHES=$(sudo journalctl -u nginx --since "5 minutes ago" | grep -c "signal" || echo 0)
if [ "$RECENT_CRASHES" -eq 0 ]; then
    echo "✓ No crashes in last 5 minutes"
else
    echo "⚠ Crashes detected: $RECENT_CRASHES in last 5 minutes"
fi

# Check for pwrite errors (the bug we fixed)
PWRITE_ERRORS=$(sudo tail -100 /var/log/nginx/error.log | grep -c "pwrite" || echo 0)
if [ "$PWRITE_ERRORS" -eq 0 ]; then
    echo "✓ No pwrite errors detected"
else
    echo "✗ pwrite errors found: $PWRITE_ERRORS"
fi

# Check hijinx log is being written
if [ -f /var/log/nginx/hijinx/hijinx.log ]; then
    LAST_LOG_TIME=$(stat -c %Y /var/log/nginx/hijinx/hijinx.log)
    CURRENT_TIME=$(date +%s)
    AGE=$((CURRENT_TIME - LAST_LOG_TIME))
    
    if [ "$AGE" -lt 3600 ]; then
        echo "✓ hijinx.log updated within last hour (${AGE}s ago)"
    else
        echo "⚠ hijinx.log not updated in $((AGE/60)) minutes"
    fi
    
    # Show recent activity
    echo ""
    echo "Recent activity (last 5 entries):"
    sudo tail -5 /var/log/nginx/hijinx/hijinx.log | sed 's/^/  /'
fi

# Check for memory leaks by monitoring worker memory
echo ""
echo "Worker process memory usage:"
ps aux | grep "nginx: worker" | grep -v grep | awk '{printf "  PID %s: %s MB (RSS)\n", $2, $6/1024}'

echo ""
echo "=== End Health Check ==="
