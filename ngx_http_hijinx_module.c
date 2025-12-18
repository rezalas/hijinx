/*
 * ngx_http_hijinx_module.c
 * 
 * Nginx module for detecting and blocking suspicious activity in real-time
 * Monitors requests for suspicious patterns and automatically blacklists IPs
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <time.h>

#define HIJINX_DEFAULT_THRESHOLD 5
#define HIJINX_HASH_SIZE 10007
#define HIJINX_MAX_PATTERNS 100

typedef struct {
    ngx_str_t   pattern;
} ngx_http_hijinx_pattern_t;

typedef struct {
    ngx_str_t   blacklist_file;
    ngx_str_t   log_dir;
    ngx_str_t   patterns_file;
    ngx_int_t   suspicion_threshold;
    ngx_flag_t  enabled;
    ngx_array_t *patterns;  /* array of ngx_http_hijinx_pattern_t */
} ngx_http_hijinx_loc_conf_t;

typedef struct {
    ngx_str_t   ip;
    ngx_int_t   count;
    time_t      last_seen;
    ngx_queue_t queue;
} ngx_http_hijinx_ip_entry_t;

typedef struct {
    ngx_queue_t     queue;
    ngx_uint_t      count;
} ngx_http_hijinx_ip_bucket_t;

static ngx_http_hijinx_ip_bucket_t *suspicious_ips_hash;
static ngx_slab_pool_t *hijinx_shpool;
static ngx_shm_zone_t *hijinx_shm_zone;

static ngx_int_t ngx_http_hijinx_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hijinx_log_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hijinx_init(ngx_conf_t *cf);
static void *ngx_http_hijinx_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_hijinx_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_hijinx_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_hijinx_init_module(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_hijinx_check_blacklist(ngx_http_request_t *r, ngx_str_t *ip);
static ngx_int_t ngx_http_hijinx_add_to_blacklist(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *request_uri);
static ngx_int_t ngx_http_hijinx_log_event(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *request_uri);
static ngx_http_hijinx_ip_entry_t *ngx_http_hijinx_lookup_ip(ngx_str_t *ip);
static ngx_int_t ngx_http_hijinx_increment_ip(ngx_http_request_t *r, ngx_str_t *ip);
static ngx_uint_t ngx_http_hijinx_hash_ip(ngx_str_t *ip);
static ngx_int_t ngx_http_hijinx_load_patterns(ngx_conf_t *cf, ngx_http_hijinx_loc_conf_t *conf);
static ngx_int_t ngx_http_hijinx_check_patterns(ngx_http_request_t *r, ngx_http_hijinx_loc_conf_t *hlcf);

static ngx_command_t ngx_http_hijinx_commands[] = {
    {
        ngx_string("hijinx"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hijinx_loc_conf_t, enabled),
        NULL
    },
    {
        ngx_string("hijinx_blacklist"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hijinx_loc_conf_t, blacklist_file),
        NULL
    },
    {
        ngx_string("hijinx_log_dir"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hijinx_loc_conf_t, log_dir),
        NULL
    },
    {
        ngx_string("hijinx_threshold"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hijinx_loc_conf_t, suspicion_threshold),
        NULL
    },
    {
        ngx_string("hijinx_patterns"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hijinx_loc_conf_t, patterns_file),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_hijinx_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_hijinx_init,                   /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_hijinx_create_loc_conf,        /* create location configuration */
    ngx_http_hijinx_merge_loc_conf          /* merge location configuration */
};

ngx_module_t ngx_http_hijinx_module = {
    NGX_MODULE_V1,
    &ngx_http_hijinx_module_ctx,            /* module context */
    ngx_http_hijinx_commands,               /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    ngx_http_hijinx_init_module,            /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_hijinx_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hijinx_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hijinx_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->suspicion_threshold = NGX_CONF_UNSET;
    conf->patterns = NULL;

    return conf;
}

static char *
ngx_http_hijinx_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hijinx_loc_conf_t *prev = parent;
    ngx_http_hijinx_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_str_value(conf->blacklist_file, prev->blacklist_file, "/etc/nginx/hijinx/blacklist.txt");
    ngx_conf_merge_str_value(conf->log_dir, prev->log_dir, "/var/log/nginx/hijinx");
    ngx_conf_merge_str_value(conf->patterns_file, prev->patterns_file, "/etc/nginx/hijinx/patterns.txt");
    ngx_conf_merge_value(conf->suspicion_threshold, prev->suspicion_threshold, HIJINX_DEFAULT_THRESHOLD);

    /* Load patterns if not already loaded */
    if (conf->patterns == NULL) {
        conf->patterns = ngx_array_create(cf->pool, 10, sizeof(ngx_http_hijinx_pattern_t));
        if (conf->patterns == NULL) {
            return NGX_CONF_ERROR;
        }
        
        if (ngx_http_hijinx_load_patterns(cf, conf) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                              "hijinx: failed to load patterns from %V, using defaults",
                              &conf->patterns_file);
        }
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_hijinx_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t len;
    ngx_uint_t i;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    hijinx_shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = hijinx_shpool->data;
        return NGX_OK;
    }

    len = sizeof(ngx_http_hijinx_ip_bucket_t) * HIJINX_HASH_SIZE;

    suspicious_ips_hash = ngx_slab_alloc(hijinx_shpool, len);
    if (suspicious_ips_hash == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < HIJINX_HASH_SIZE; i++) {
        ngx_queue_init(&suspicious_ips_hash[i].queue);
        suspicious_ips_hash[i].count = 0;
    }

    hijinx_shpool->data = suspicious_ips_hash;
    shm_zone->data = suspicious_ips_hash;

    return NGX_OK;
}

static ngx_int_t
ngx_http_hijinx_init_module(ngx_cycle_t *cycle)
{
    ngx_str_t name = ngx_string("hijinx_zone");
    size_t size = 10 * 1024 * 1024; /* 10MB shared memory */

    hijinx_shm_zone = ngx_shared_memory_add(cycle->conf_ctx, &name, size, 
                                            &ngx_http_hijinx_module);
    if (hijinx_shm_zone == NULL) {
        return NGX_ERROR;
    }

    hijinx_shm_zone->init = ngx_http_hijinx_init_zone;

    return NGX_OK;
}

static ngx_int_t
ngx_http_hijinx_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Register access phase handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_hijinx_handler;

    /* Register log phase handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_hijinx_log_handler;

    return NGX_OK;
}

static ngx_uint_t
ngx_http_hijinx_hash_ip(ngx_str_t *ip)
{
    ngx_uint_t hash = 0;
    ngx_uint_t i;

    for (i = 0; i < ip->len; i++) {
        hash = hash * 31 + ip->data[i];
    }

    return hash % HIJINX_HASH_SIZE;
}

static ngx_http_hijinx_ip_entry_t *
ngx_http_hijinx_lookup_ip(ngx_str_t *ip)
{
    ngx_uint_t hash;
    ngx_queue_t *q;
    ngx_http_hijinx_ip_entry_t *entry;

    if (suspicious_ips_hash == NULL) {
        return NULL;
    }

    hash = ngx_http_hijinx_hash_ip(ip);

    for (q = ngx_queue_head(&suspicious_ips_hash[hash].queue);
         q != ngx_queue_sentinel(&suspicious_ips_hash[hash].queue);
         q = ngx_queue_next(q))
    {
        entry = ngx_queue_data(q, ngx_http_hijinx_ip_entry_t, queue);

        if (entry->ip.len == ip->len && 
            ngx_strncmp(entry->ip.data, ip->data, ip->len) == 0) {
            return entry;
        }
    }

    return NULL;
}

static ngx_int_t
ngx_http_hijinx_increment_ip(ngx_http_request_t *r, ngx_str_t *ip)
{
    ngx_uint_t hash;
    ngx_http_hijinx_ip_entry_t *entry;
    u_char *ip_copy;

    entry = ngx_http_hijinx_lookup_ip(ip);

    if (entry != NULL) {
        entry->count++;
        entry->last_seen = ngx_time();
        return entry->count;
    }

    /* Create new entry */
    hash = ngx_http_hijinx_hash_ip(ip);

    entry = ngx_slab_alloc_locked(hijinx_shpool, sizeof(ngx_http_hijinx_ip_entry_t));
    if (entry == NULL) {
        return NGX_ERROR;
    }

    ip_copy = ngx_slab_alloc_locked(hijinx_shpool, ip->len);
    if (ip_copy == NULL) {
        ngx_slab_free_locked(hijinx_shpool, entry);
        return NGX_ERROR;
    }

    ngx_memcpy(ip_copy, ip->data, ip->len);

    entry->ip.data = ip_copy;
    entry->ip.len = ip->len;
    entry->count = 1;
    entry->last_seen = ngx_time();

    ngx_queue_insert_head(&suspicious_ips_hash[hash].queue, &entry->queue);
    suspicious_ips_hash[hash].count++;

    return entry->count;
}

static ngx_int_t
ngx_http_hijinx_check_blacklist(ngx_http_request_t *r, ngx_str_t *ip)
{
    ngx_file_t file;
    ngx_http_hijinx_loc_conf_t *hlcf;
    u_char buf[4096];
    ssize_t n;
    u_char *p, *last;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = hlcf->blacklist_file;
    file.log = r->connection->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_DECLINED;
    }

    for (;;) {
        n = ngx_read_file(&file, buf, sizeof(buf), 0);
        if (n == NGX_ERROR) {
            ngx_close_file(file.fd);
            return NGX_DECLINED;
        }

        if (n == 0) {
            break;
        }

        p = buf;
        last = buf + n;

        while (p < last) {
            u_char *line_start = p;
            u_char *line_end = p;

            while (line_end < last && *line_end != '\n') {
                line_end++;
            }

            size_t line_len = line_end - line_start;

            /* Trim whitespace */
            while (line_len > 0 && (line_start[line_len - 1] == ' ' || 
                                   line_start[line_len - 1] == '\r' || 
                                   line_start[line_len - 1] == '\n')) {
                line_len--;
            }

            if (line_len == ip->len && ngx_strncmp(line_start, ip->data, ip->len) == 0) {
                ngx_close_file(file.fd);
                return NGX_HTTP_FORBIDDEN;
            }

            p = line_end + 1;
        }
    }

    ngx_close_file(file.fd);
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_hijinx_add_to_blacklist(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *request_uri)
{
    ngx_file_t file;
    ngx_http_hijinx_loc_conf_t *hlcf;
    u_char buf[1024];
    size_t len;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);

    /* Check if already in blacklist */
    if (ngx_http_hijinx_check_blacklist(r, ip) == NGX_HTTP_FORBIDDEN) {
        return NGX_OK;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = hlcf->blacklist_file;
    file.log = r->connection->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_WRONLY, NGX_FILE_APPEND, 
                            NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    len = ngx_snprintf(buf, sizeof(buf), "%V\n", ip) - buf;
    ngx_write_file(&file, buf, len, file.offset);

    ngx_close_file(file.fd);

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "hijinx: Added %V to blacklist due to suspicious activity", ip);

    /* Log the event */
    ngx_http_hijinx_log_event(r, ip, request_uri);

    return NGX_OK;
}

static ngx_int_t
ngx_http_hijinx_log_event(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *request_uri)
{
    ngx_file_t file;
    ngx_http_hijinx_loc_conf_t *hlcf;
    u_char buf[2048];
    u_char logpath[512];
    u_char timebuf[64];
    size_t len;
    struct tm *tm;
    time_t now;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);

    /* Use standard log file path: hijinx.log */
    now = ngx_time();
    tm = localtime(&now);
    
    ngx_memzero(&file, sizeof(ngx_file_t));
    
    len = ngx_snprintf(logpath, sizeof(logpath), "%V/hijinx.log",
                      &hlcf->log_dir) - logpath;
    
    file.name.data = logpath;
    file.name.len = len;
    file.log = r->connection->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    ngx_snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02d %02d:%02d:%02d",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);

    len = ngx_snprintf(buf, sizeof(buf), "%s - %V - Added to blacklist thanks to final straw - %V\n",
                      timebuf, ip, request_uri) - buf;

    ngx_write_file(&file, buf, len, file.offset);
    ngx_close_file(file.fd);

    return NGX_OK;
}

static ngx_int_t
ngx_http_hijinx_handler(ngx_http_request_t *r)
{
    ngx_http_hijinx_loc_conf_t *hlcf;
    ngx_str_t ip;
    ngx_int_t count;
    ngx_int_t is_suspicious = 0;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);

    if (!hlcf->enabled) {
        return NGX_DECLINED;
    }

    /* Get client IP */
    ip = r->connection->addr_text;

    /* First check if IP is already blacklisted */
    if (ngx_http_hijinx_check_blacklist(r, &ip) == NGX_HTTP_FORBIDDEN) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "hijinx: Blocked request from blacklisted IP: %V", &ip);
        return NGX_HTTP_FORBIDDEN;
    }

    /* Check for suspicious patterns in the request */
    is_suspicious = ngx_http_hijinx_check_patterns(r, hlcf);

    /* Only track if suspicious pattern detected */
    if (is_suspicious) {
        /* We'll check the response status in the log phase handler */
        /* Store flag in request context */
        ngx_http_set_ctx(r, (void *) 1, ngx_http_hijinx_module);
    }

    return NGX_DECLINED;
}

/* Log phase handler to check response status */
static ngx_int_t
ngx_http_hijinx_log_handler(ngx_http_request_t *r)
{
    ngx_http_hijinx_loc_conf_t *hlcf;
    ngx_str_t ip;
    ngx_int_t count;
    void *ctx;

    /* Check if this request was flagged as suspicious */
    ctx = ngx_http_get_module_ctx(r, ngx_http_hijinx_module);
    if (ctx == NULL) {
        return NGX_OK;
    }

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);

    if (!hlcf->enabled) {
        return NGX_OK;
    }

    ip = r->connection->addr_text;

    /* Check if response was 403 or 404 */
    if (r->headers_out.status == 403 || r->headers_out.status == 404) {
        
        ngx_shmtx_lock(&hijinx_shpool->mutex);
        count = ngx_http_hijinx_increment_ip(r, &ip);
        ngx_shmtx_unlock(&hijinx_shpool->mutex);

        if (count >= hlcf->suspicion_threshold) {
            ngx_http_hijinx_add_to_blacklist(r, &ip, &r->uri);
        }
    }

    return NGX_OK;
}

/* Load patterns from file */
static ngx_int_t
ngx_http_hijinx_load_patterns(ngx_conf_t *cf, ngx_http_hijinx_loc_conf_t *conf)
{
    ngx_file_t file;
    u_char buf[4096];
    ssize_t n;
    u_char *p, *last, *line_start, *line_end;
    ngx_http_hijinx_pattern_t *pattern;
    ngx_uint_t line_num = 0;
    size_t line_len;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = conf->patterns_file;
    file.log = cf->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        /* If file doesn't exist, add default patterns */
        pattern = ngx_array_push(conf->patterns);
        if (pattern == NULL) {
            return NGX_ERROR;
        }
        pattern->pattern.data = (u_char *) "/admin";
        pattern->pattern.len = 6;

        pattern = ngx_array_push(conf->patterns);
        if (pattern == NULL) {
            return NGX_ERROR;
        }
        pattern->pattern.data = (u_char *) "/login";
        pattern->pattern.len = 6;

        pattern = ngx_array_push(conf->patterns);
        if (pattern == NULL) {
            return NGX_ERROR;
        }
        pattern->pattern.data = (u_char *) ".php";
        pattern->pattern.len = 4;

        return NGX_OK;
    }

    /* Read and parse patterns file */
    for (;;) {
        n = ngx_read_file(&file, buf, sizeof(buf), 0);
        if (n == NGX_ERROR) {
            ngx_close_file(file.fd);
            return NGX_ERROR;
        }

        if (n == 0) {
            break;
        }

        p = buf;
        last = buf + n;

        while (p < last) {
            line_start = p;
            line_end = p;

            /* Find end of line */
            while (line_end < last && *line_end != '\n') {
                line_end++;
            }

            line_num++;
            line_len = line_end - line_start;

            /* Trim trailing whitespace */
            while (line_len > 0 && (line_start[line_len - 1] == ' ' ||
                                   line_start[line_len - 1] == '\r' ||
                                   line_start[line_len - 1] == '\n' ||
                                   line_start[line_len - 1] == '\t')) {
                line_len--;
            }

            /* Trim leading whitespace */
            while (line_len > 0 && (*line_start == ' ' || *line_start == '\t')) {
                line_start++;
                line_len--;
            }

            /* Skip empty lines and comments */
            if (line_len == 0 || *line_start == '#') {
                p = line_end + 1;
                continue;
            }

            /* Check max patterns */
            if (conf->patterns->nelts >= HIJINX_MAX_PATTERNS) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                  \"hijinx: maximum patterns (%d) reached, ignoring remaining\",
                                  HIJINX_MAX_PATTERNS);
                break;
            }

            /* Add pattern */
            pattern = ngx_array_push(conf->patterns);
            if (pattern == NULL) {
                ngx_close_file(file.fd);
                return NGX_ERROR;
            }

            pattern->pattern.data = ngx_pnalloc(cf->pool, line_len);
            if (pattern->pattern.data == NULL) {
                ngx_close_file(file.fd);
                return NGX_ERROR;
            }

            ngx_memcpy(pattern->pattern.data, line_start, line_len);
            pattern->pattern.len = line_len;

            p = line_end + 1;
        }
    }

    ngx_close_file(file.fd);

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                      \"hijinx: loaded %ui patterns from %V\",
                      conf->patterns->nelts, &conf->patterns_file);

    return NGX_OK;
}

/* Check if URI matches any suspicious patterns */
static ngx_int_t
ngx_http_hijinx_check_patterns(ngx_http_request_t *r, ngx_http_hijinx_loc_conf_t *hlcf)
{
    ngx_uint_t i;
    ngx_http_hijinx_pattern_t *patterns;

    if (hlcf->patterns == NULL || hlcf->patterns->nelts == 0) {
        return 0;
    }

    patterns = hlcf->patterns->elts;

    for (i = 0; i < hlcf->patterns->nelts; i++) {
        if (ngx_strstrn(r->uri.data, (char *) patterns[i].pattern.data,
                       patterns[i].pattern.len - 1) != NULL) {
            return 1;
        }
    }

    return 0;
}