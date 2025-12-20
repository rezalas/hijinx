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
#define HIJINX_MAX_HTML_FILES 50

/* Debug logging macro - only logs if hijinx_debug is enabled */
#define hijinx_debug_log(r, hlcf, ...) \
    if (hlcf->debug) { \
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, __VA_ARGS__); \
    }

typedef struct {
    ngx_str_t   pattern;
} ngx_http_hijinx_pattern_t;

typedef struct {
    ngx_str_t   content;
} ngx_http_hijinx_html_t;

typedef struct {
    ngx_str_t   blacklist_file;
    ngx_str_t   log_dir;
    ngx_str_t   patterns_file;
    ngx_str_t   html_dir;
    ngx_int_t   suspicion_threshold;
    ngx_flag_t  enabled;
    ngx_flag_t  serve_random_content;
    ngx_flag_t  debug;
    ngx_flag_t  patterns_loaded; /* flag to track if patterns have been loaded */
    ngx_flag_t  html_files_loaded; /* flag to track if HTML files have been loaded */
    ngx_array_t *patterns;  /* array of ngx_http_hijinx_pattern_t */
    ngx_array_t *html_files; /* array of ngx_http_hijinx_html_t */
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
static ngx_int_t ngx_http_hijinx_load_html_files(ngx_conf_t *cf, ngx_http_hijinx_loc_conf_t *conf);
static ngx_int_t ngx_http_hijinx_serve_random_html(ngx_http_request_t *r, ngx_http_hijinx_loc_conf_t *hlcf);
static ngx_int_t ngx_http_hijinx_serve_random_html_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_hijinx_log_random_content(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *request_uri, ngx_uint_t file_index, ngx_uint_t status);
static void ngx_http_hijinx_log_error(ngx_http_request_t *r, const char *message);
static char *ngx_http_hijinx_patterns(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_hijinx_html_dir(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

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
        ngx_http_hijinx_patterns,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("hijinx_serve_random_content"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hijinx_loc_conf_t, serve_random_content),
        NULL
    },
    {
        ngx_string("hijinx_html_dir"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_hijinx_html_dir,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("hijinx_debug"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hijinx_loc_conf_t, debug),
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

static char *
ngx_http_hijinx_patterns(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_hijinx_loc_conf_t *hlcf = conf;
    ngx_str_t *value;

    value = cf->args->elts;
    hlcf->patterns_file = value[1];

    /* Only load patterns once per config structure */
    if (!hlcf->patterns_loaded) {
        if (hlcf->patterns == NULL) {
            hlcf->patterns = ngx_array_create(cf->pool, 10, sizeof(ngx_http_hijinx_pattern_t));
            if (hlcf->patterns == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (ngx_http_hijinx_load_patterns(cf, hlcf) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                              "hijinx: failed to load patterns from %V, using defaults",
                              &hlcf->patterns_file);
        }
        
        hlcf->patterns_loaded = 1;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_hijinx_html_dir(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_hijinx_loc_conf_t *hlcf = conf;
    ngx_str_t *value;

    value = cf->args->elts;
    hlcf->html_dir = value[1];

    /* Only load HTML files once per config structure */
    if (!hlcf->html_files_loaded) {
        if (hlcf->html_files == NULL) {
            hlcf->html_files = ngx_array_create(cf->pool, 10, sizeof(ngx_http_hijinx_html_t));
            if (hlcf->html_files == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (ngx_http_hijinx_load_html_files(cf, hlcf) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                              "hijinx: failed to load HTML files from %V",
                              &hlcf->html_dir);
        }
        
        hlcf->html_files_loaded = 1;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_hijinx_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_hijinx_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_hijinx_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->serve_random_content = NGX_CONF_UNSET;
    conf->debug = NGX_CONF_UNSET;
    conf->suspicion_threshold = NGX_CONF_UNSET;
    conf->patterns_loaded = 0;
    conf->html_files_loaded = 0;
    conf->patterns = NULL;
    conf->html_files = NULL;

    return conf;
}

static char *
ngx_http_hijinx_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_hijinx_loc_conf_t *prev = parent;
    ngx_http_hijinx_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_value(conf->serve_random_content, prev->serve_random_content, 0);
    ngx_conf_merge_value(conf->debug, prev->debug, 0);

    if (conf->debug) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                          "hijinx: merge_loc_conf - enabled=%d, serve_random=%d",
                          conf->enabled, conf->serve_random_content);
    }
    ngx_conf_merge_str_value(conf->blacklist_file, prev->blacklist_file, "/etc/nginx/hijinx/blacklist.txt");
    ngx_conf_merge_str_value(conf->log_dir, prev->log_dir, "/var/log/nginx/hijinx");
    ngx_conf_merge_str_value(conf->patterns_file, prev->patterns_file, "/etc/nginx/hijinx/patterns.txt");
    ngx_conf_merge_str_value(conf->html_dir, prev->html_dir, "/etc/nginx/hijinx/html");
    ngx_conf_merge_value(conf->suspicion_threshold, prev->suspicion_threshold, HIJINX_DEFAULT_THRESHOLD);

    /* Simply inherit pointers from parent - don't load anything here  */
    if (conf->patterns == NULL) {
        conf->patterns = prev->patterns;
        conf->patterns_loaded = prev->patterns_loaded;
    }

    if (conf->html_files == NULL) {
        conf->html_files = prev->html_files;
        conf->html_files_loaded = prev->html_files_loaded;
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
    /* Module initialization - nothing to do here, 
     * shared memory is set up in ngx_http_hijinx_init */
    return NGX_OK;
}

static ngx_int_t
ngx_http_hijinx_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_str_t name = ngx_string("hijinx_zone");
    size_t size = 10 * 1024 * 1024; /* 10MB shared memory */

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Initialize shared memory zone */
    hijinx_shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_hijinx_module);
    if (hijinx_shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "hijinx: failed to add shared memory zone");
        return NGX_ERROR;
    }

    hijinx_shm_zone->init = ngx_http_hijinx_init_zone;

    /* Register access phase handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "hijinx: failed to register access phase handler");
        return NGX_ERROR;
    }
    *h = ngx_http_hijinx_handler;

    /* Register log phase handler */
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                          "hijinx: failed to register log phase handler");
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
    off_t offset = 0;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = hlcf->blacklist_file;
    file.log = r->connection->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_DECLINED;
    }

    for (;;) {
        n = ngx_read_file(&file, buf, sizeof(buf), offset);
        if (n == NGX_ERROR) {
            ngx_close_file(file.fd);
            return NGX_DECLINED;
        }

        if (n == 0) {
            break;
        }

        offset += n;

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

    file.fd = ngx_open_file(file.name.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    ngx_snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02d %02d:%02d:%02d",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);

    len = ngx_snprintf(buf, sizeof(buf), "%s - %V - Added to blacklist thanks to final straw - %V\n",
                      timebuf, ip, request_uri) - buf;

    /* Use direct write() since file is opened in append mode */
    if (write(file.fd, buf, len) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                     "hijinx: Failed to write to hijinx.log");
    }
    
    ngx_close_file(file.fd);

    return NGX_OK;
}

/* Log random content serving events */
static ngx_int_t
ngx_http_hijinx_log_random_content(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *request_uri, ngx_uint_t file_index, ngx_uint_t status)
{
    ngx_file_t file;
    ngx_http_hijinx_loc_conf_t *hlcf;
    u_char buf[4096];
    u_char logpath[512];
    u_char timebuf[64];
    size_t pathlen, buflen;
    struct tm *tm;
    time_t now;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);

    now = ngx_time();
    tm = localtime(&now);
    
    ngx_memzero(&file, sizeof(ngx_file_t));
    
    pathlen = ngx_snprintf(logpath, sizeof(logpath), "%V/hijinx.log",
                           &hlcf->log_dir) - logpath;
    
    logpath[pathlen] = '\0';  /* Ensure null termination */
    
    file.name.data = logpath;
    file.name.len = pathlen;
    file.log = r->connection->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                     "hijinx: Failed to open hijinx.log for random content logging");
        return NGX_ERROR;
    }

    ngx_snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02d %02d:%02d:%02d",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);

    /* Log format: timestamp - IP - served info - URI | Original request in access.log format */
    buflen = ngx_snprintf(buf, sizeof(buf), 
                          "%s - %V - Served random content (file #%ui) - %V | %V %V %V %ui\n",
                          timebuf, ip, file_index, request_uri,
                          &r->method_name, &r->unparsed_uri, 
                          &r->http_protocol, status) - buf;

    /* Write directly since file is opened in append mode */
    if (write(file.fd, buf, buflen) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                     "hijinx: Failed to write to hijinx.log");
    }
    
    ngx_close_file(file.fd);

    return NGX_OK;
}

/* Log errors to hijinx-error.log */
static void
ngx_http_hijinx_log_error(ngx_http_request_t *r, const char *message)
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

    now = ngx_time();
    tm = localtime(&now);
    
    ngx_memzero(&file, sizeof(ngx_file_t));
    
    len = ngx_snprintf(logpath, sizeof(logpath), "%V/hijinx-error.log",
                      &hlcf->log_dir) - logpath;
    
    file.name.data = logpath;
    file.name.len = len;
    file.log = r->connection->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN,
                            NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        /* Can't write to error log, just log to nginx error log */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "hijinx: Failed to open hijinx-error.log: %s", message);
        return;
    }

    ngx_snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02d %02d:%02d:%02d",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec);

    len = ngx_snprintf(buf, sizeof(buf), "%s - ERROR - %s\n",
                      timebuf, message) - buf;

    /* Write directly since file is opened in append mode */
    if (write(file.fd, buf, len) == -1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                     "hijinx: Failed to write to hijinx-error.log");
    }
    
    ngx_close_file(file.fd);
}

static ngx_int_t
ngx_http_hijinx_handler(ngx_http_request_t *r)
{
    ngx_http_hijinx_loc_conf_t *hlcf;
    ngx_str_t ip;
    ngx_int_t is_suspicious = 0;

    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);
    
    /* Skip internal requests to avoid duplicate processing */
    if (r->internal) {
        return NGX_DECLINED;
    }
    
    hijinx_debug_log(r, hlcf, "hijinx: Handler entered for URI=%V", &r->uri);

    if (!hlcf->enabled) {
        return NGX_DECLINED;
    }

    /* Get client IP */
    ip = r->connection->addr_text;
    
    hijinx_debug_log(r, hlcf, "hijinx: Got IP=%V, checking blacklist", &ip);

    /* First check if IP is already blacklisted */
    ngx_int_t blacklist_result = ngx_http_hijinx_check_blacklist(r, &ip);
    
    if (blacklist_result == NGX_HTTP_FORBIDDEN) {
        hijinx_debug_log(r, hlcf, "hijinx: IP %V is blacklisted, serving fake content", &ip);
        /* Serve fake HTML to blacklisted IPs instead of returning 403 */
        if (hlcf->serve_random_content) {
            /* Set the content handler to serve random HTML */
            r->content_handler = ngx_http_hijinx_serve_random_html_content_handler;
            return NGX_DECLINED;
        }
        return NGX_HTTP_FORBIDDEN;
    }

    /* Check for suspicious patterns in the request */
    is_suspicious = ngx_http_hijinx_check_patterns(r, hlcf);
    
    hijinx_debug_log(r, hlcf, "hijinx: Pattern check for %V: is_suspicious=%d", &r->uri, is_suspicious);

    /* Only track if suspicious pattern detected */
    if (is_suspicious) {
        /* If serve_random_content is enabled, increment counter */
        if (hlcf->serve_random_content) {
            ngx_int_t count = 0;
            
            /* Check if shared memory is initialized */
            if (hijinx_shpool != NULL) {
                /* Increment IP counter */
                ngx_shmtx_lock(&hijinx_shpool->mutex);
                count = ngx_http_hijinx_increment_ip(r, &ip);
                ngx_shmtx_unlock(&hijinx_shpool->mutex);
                
                hijinx_debug_log(r, hlcf, "hijinx: IP %V count is now %d (threshold=%d)",
                              &ip, count, hlcf->suspicion_threshold);
                
                /* Check if we've reached the threshold */
                if (count >= hlcf->suspicion_threshold) {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                                  "hijinx: Threshold reached! Adding IP %V to blacklist", &ip);
                    ngx_http_hijinx_add_to_blacklist(r, &ip, &r->uri);
                }
            }
        }
        
        /* Store flag in request context for log phase */
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
        
        /* Check if shared memory is initialized */
        if (hijinx_shpool != NULL) {
            ngx_shmtx_lock(&hijinx_shpool->mutex);
            count = ngx_http_hijinx_increment_ip(r, &ip);
            ngx_shmtx_unlock(&hijinx_shpool->mutex);

            if (count >= hlcf->suspicion_threshold) {
                ngx_http_hijinx_add_to_blacklist(r, &ip, &r->uri);
            }
        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "hijinx: shared memory not initialized in log handler");
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
    size_t line_len;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = conf->patterns_file;
    file.log = cf->log;

    file.fd = ngx_open_file(file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        /* If file doesn't exist, add default patterns - allocate them properly */
        u_char *default_patterns[] = {(u_char *)"/admin", (u_char *)"/login", (u_char *)".php"};
        size_t default_lens[] = {6, 6, 4};
        ngx_uint_t i;
        
        for (i = 0; i < 3; i++) {
            pattern = ngx_array_push(conf->patterns);
            if (pattern == NULL) {
                return NGX_ERROR;
            }
            
            pattern->pattern.len = default_lens[i];
            pattern->pattern.data = ngx_pnalloc(cf->pool, default_lens[i]);
            if (pattern->pattern.data == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(pattern->pattern.data, default_patterns[i], default_lens[i]);
        }

        return NGX_OK;
    }

    /* Read and parse patterns file */
    off_t offset = 0;
    ngx_flag_t max_reached = 0;
    
    for (;;) {
        if (max_reached) {
            break;
        }
        
        n = ngx_read_file(&file, buf, sizeof(buf), offset);
        if (n == NGX_ERROR) {
            ngx_close_file(file.fd);
            return NGX_ERROR;
        }

        if (n == 0) {
            break;
        }

        offset += n;
        p = buf;
        last = buf + n;

        while (p < last) {
            line_start = p;
            line_end = p;

            /* Find end of line */
            while (line_end < last && *line_end != '\n') {
                line_end++;
            }

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
                if (!max_reached) {
                    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                      "hijinx: maximum patterns (%d) reached, ignoring remaining",
                                      HIJINX_MAX_PATTERNS);
                    max_reached = 1;
                }
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
                      "hijinx: loaded %ui patterns from %V",
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
        /* Check if pattern is contained in URI - simple substring search */
        if (r->uri.len >= patterns[i].pattern.len) {
            size_t j;
            ngx_flag_t found = 0;
            
            /* Search for pattern in URI */
            for (j = 0; j <= r->uri.len - patterns[i].pattern.len; j++) {
                if (ngx_memcmp(r->uri.data + j, patterns[i].pattern.data, 
                              patterns[i].pattern.len) == 0) {
                    found = 1;
                    break;
                }
            }
            
            if (found) {
                hijinx_debug_log(r, hlcf, "hijinx: URI '%V' matches pattern '%V'", 
                              &r->uri, &patterns[i].pattern);
                return 1;
            }
        }
    }

    return 0;
}

/* Load HTML files from directory for random content serving */
static ngx_int_t
ngx_http_hijinx_load_html_files(ngx_conf_t *cf, ngx_http_hijinx_loc_conf_t *conf)
{
    ngx_dir_t dir;
    ngx_file_info_t fi;
    ngx_str_t path;
    u_char *filename;
    size_t len;
    ngx_file_t file;
    u_char buf[8192];
    ssize_t n, total;
    ngx_http_hijinx_html_t *html;

    if (ngx_open_dir(&conf->html_dir, &dir) == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, ngx_errno,
                          "hijinx: failed to open HTML directory %V", &conf->html_dir);
        return NGX_ERROR;
    }

    for (;;) {
        ngx_set_errno(0);
        
        if (ngx_read_dir(&dir) == NGX_ERROR) {
            break;  /* Don't close here - will be closed after loop */
        }

        filename = ngx_de_name(&dir);
        len = ngx_de_namelen(&dir);

        if (len == 1 && filename[0] == '.') {
            continue;
        }
        if (len == 2 && filename[0] == '.' && filename[1] == '.') {
            continue;
        }

        /* Only load .html files */
        if (len < 5 || ngx_strncmp(filename + len - 5, ".html", 5) != 0) {
            continue;
        }

        /* Check max HTML files */
        if (conf->html_files->nelts >= HIJINX_MAX_HTML_FILES) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                              "hijinx: maximum HTML files (%d) reached, ignoring remaining",
                              HIJINX_MAX_HTML_FILES);
            break;  /* Don't close here - will be closed after loop */
        }

        /* Build full path */
        path.len = conf->html_dir.len + 1 + len;
        path.data = ngx_pnalloc(cf->pool, path.len + 1);
        if (path.data == NULL) {
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        ngx_sprintf(path.data, "%V/%s%Z", &conf->html_dir, filename);

        /* Read file content */
        ngx_memzero(&file, sizeof(ngx_file_t));
        file.name = path;
        file.log = cf->log;

        file.fd = ngx_open_file(path.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
        if (file.fd == NGX_INVALID_FILE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, ngx_errno,
                              "hijinx: failed to open HTML file %V", &path);
            continue;
        }

        if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
            ngx_close_file(file.fd);
            continue;
        }

        if (ngx_is_dir(&fi)) {
            ngx_close_file(file.fd);
            continue;
        }

        /* Allocate memory for HTML content */
        html = ngx_array_push(conf->html_files);
        if (html == NULL) {
            ngx_close_file(file.fd);
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        html->content.len = ngx_file_size(&fi);
        html->content.data = ngx_pnalloc(cf->pool, html->content.len);
        if (html->content.data == NULL) {
            ngx_close_file(file.fd);
            ngx_close_dir(&dir);
            return NGX_ERROR;
        }

        /* Read entire file into memory */
        total = 0;
        while (total < (ssize_t) html->content.len) {
            n = ngx_read_file(&file, buf, sizeof(buf), total);
            if (n == NGX_ERROR) {
                ngx_close_file(file.fd);
                ngx_close_dir(&dir);
                return NGX_ERROR;
            }
            if (n == 0) {
                break;
            }
            ngx_memcpy(html->content.data + total, buf, n);
            total += n;
        }

        ngx_close_file(file.fd);
    }

    ngx_close_dir(&dir);

    if (conf->html_files->nelts == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                          "hijinx: no HTML files found in %V", &conf->html_dir);
        return NGX_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_INFO, cf, 0,
                      "hijinx: loaded %ui HTML files from %V",
                      conf->html_files->nelts, &conf->html_dir);

    return NGX_OK;
}

/* Content phase handler wrapper for serving random HTML */
static ngx_int_t
ngx_http_hijinx_serve_random_html_content_handler(ngx_http_request_t *r)
{
    ngx_http_hijinx_loc_conf_t *hlcf;
    
    hlcf = ngx_http_get_module_loc_conf(r, ngx_http_hijinx_module);
    return ngx_http_hijinx_serve_random_html(r, hlcf);
}

/* Serve random HTML content from loaded files */
static ngx_int_t
ngx_http_hijinx_serve_random_html(ngx_http_request_t *r, ngx_http_hijinx_loc_conf_t *hlcf)
{
    ngx_http_hijinx_html_t *html_files;
    ngx_http_hijinx_html_t *selected;
    ngx_uint_t index;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_str_t ip;
    ngx_int_t rc;

    if (hlcf->html_files == NULL || hlcf->html_files->nelts == 0) {
        /* No HTML files loaded, log error and return 404 */
        ngx_http_hijinx_log_error(r, "No HTML files loaded for random content serving");
        return NGX_HTTP_NOT_FOUND;
    }

    html_files = hlcf->html_files->elts;

    /* Randomly select an HTML file */
    /* Use simple pseudo-random selection based on current time and IP */
    index = (ngx_time() + r->connection->number) % hlcf->html_files->nelts;
    selected = &html_files[index];

    /* Get client IP for logging */
    ip = r->connection->addr_text;

    /* Log the random content serving event */
    ngx_http_hijinx_log_random_content(r, &ip, &r->uri, index, NGX_HTTP_OK);

    /* Discard request body */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Set response status */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = selected->content.len;

    /* Set content type */
    ngx_str_set(&r->headers_out.content_type, "text/html");
    r->headers_out.content_type_len = sizeof("text/html") - 1;

    /* Send headers */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    /* Create buffer with HTML content */
    b = ngx_create_temp_buf(r->pool, selected->content.len);
    if (b == NULL) {
        ngx_http_hijinx_log_error(r, "Failed to allocate buffer for random content");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, selected->content.data, selected->content.len);
    b->last = b->pos + selected->content.len;
    b->last_buf = 1;
    b->last_in_chain = 1;

    /* Send body */
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}