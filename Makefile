# Makefile for Hijinx Nginx Module
# 
# Usage:
#   make config       - Configure nginx with the module
#   make build        - Build the module
#   make install      - Install the module
#   make clean        - Clean build artifacts
#   make test         - Test nginx configuration

# Configuration
NGINX_VERSION ?= 1.24.0
NGINX_DIR ?= ../nginx-$(NGINX_VERSION)
MODULE_DIR := $(shell pwd)
INSTALL_DIR ?= /usr/share/nginx/modules

# Colors for output
COLOR_RESET = \033[0m
COLOR_GREEN = \033[32m
COLOR_YELLOW = \033[33m
COLOR_BLUE = \033[34m

.PHONY: help config build install enable disable clean test setup logrotate

help:
	@echo "$(COLOR_BLUE)Hijinx Nginx Module - Build System$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_GREEN)Available targets:$(COLOR_RESET)"
	@echo "  make setup       - Create required directories and files"
	@echo "  make config      - Configure nginx with the hijinx module"
	@echo "  make build       - Build the dynamic module"
	@echo "  make install     - Install the module to nginx and logrotate"
	@echo "  make enable      - Enable the module (create symlink)"
	@echo "  make disable     - Disable the module (remove symlink)"
	@echo "  make logrotate   - Install logrotate configuration only"
	@echo "  make clean       - Clean build artifacts"
	@echo "  make test        - Test nginx configuration"
	@echo "  make all         - Run setup, config, build, and install"
	@echo ""
	@echo "$(COLOR_YELLOW)Variables:$(COLOR_RESET)"
	@echo "  NGINX_DIR=$(NGINX_DIR)"
	@echo "  MODULE_DIR=$(MODULE_DIR)"
	@echo "  INSTALL_DIR=$(INSTALL_DIR)"
	@echo ""
	@echo "$(COLOR_YELLOW)Note:$(COLOR_RESET)"
	@echo "  Module installs to: $(INSTALL_DIR)/"
	@echo "  Config installs to: /etc/nginx/modules-available/"
	@echo "  Load via: /etc/nginx/modules-enabled/mod_http_hijinx.conf"

setup:
	@echo "$(COLOR_GREEN)Setting up hijinx directories...$(COLOR_RESET)"
	@sudo mkdir -p /etc/nginx/hijinx
	@sudo mkdir -p /var/log/nginx/hijinx
	@sudo mkdir -p /etc/nginx/modules-available 2>/dev/null || true
	@sudo mkdir -p /etc/nginx/modules-enabled 2>/dev/null || true
	@sudo touch /etc/nginx/hijinx/blacklist.txt
	@sudo chmod 644 /etc/nginx/hijinx/blacklist.txt
	@echo "$(COLOR_BLUE)Installing configuration files...$(COLOR_RESET)"
	@if [ ! -f /etc/nginx/hijinx/patterns.txt ]; then \
		sudo cp patterns.txt /etc/nginx/hijinx/patterns.txt; \
		sudo chmod 644 /etc/nginx/hijinx/patterns.txt; \
		echo "$(COLOR_GREEN)Installed patterns.txt$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)patterns.txt already exists, not overwriting$(COLOR_RESET)"; \
	fi
	@if [ ! -f /etc/nginx/hijinx/hijinx-nginx.conf ]; then \
		sudo cp hijinx-nginx.conf /etc/nginx/hijinx/hijinx-nginx.conf; \
		sudo chmod 644 /etc/nginx/hijinx/hijinx-nginx.conf; \
		echo "$(COLOR_GREEN)Installed hijinx-nginx.conf$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)hijinx-nginx.conf already exists, not overwriting$(COLOR_RESET)"; \
	fi
	@if [ ! -f /etc/nginx/hijinx/config_template.conf ]; then \
		sudo cp config_template.conf /etc/nginx/hijinx/config_template.conf; \
		sudo chmod 644 /etc/nginx/hijinx/config_template.conf; \
		echo "$(COLOR_GREEN)Installed config_template.conf$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_YELLOW)config_template.conf already exists, not overwriting$(COLOR_RESET)"; \
	fi
	@echo "$(COLOR_BLUE)Installing HTML files for random content serving...$(COLOR_RESET)"
	@sudo mkdir -p /etc/nginx/hijinx/html
	@sudo cp -n html/*.html /etc/nginx/hijinx/html/ 2>/dev/null || true
	@sudo chmod 644 /etc/nginx/hijinx/html/*.html 2>/dev/null || true
	@echo "$(COLOR_GREEN)Installed HTML files$(COLOR_RESET)"
	@sudo chown -R nginx:nginx /etc/nginx/hijinx 2>/dev/null || \
		sudo chown -R www-data:www-data /etc/nginx/hijinx 2>/dev/null || \
		sudo chown -R $$USER:$$USER /etc/nginx/hijinx
	@sudo chown -R nginx:nginx /var/log/nginx/hijinx 2>/dev/null || \
		sudo chown -R www-data:www-data /var/log/nginx/hijinx 2>/dev/null || \
		sudo chown -R $$USER:$$USER /var/log/nginx/hijinx
	@echo "$(COLOR_GREEN)Setup complete!$(COLOR_RESET)"

config:
	@echo "$(COLOR_GREEN)Configuring nginx with hijinx module...$(COLOR_RESET)"
	@if [ ! -d "$(NGINX_DIR)" ]; then \
		echo "$(COLOR_YELLOW)Nginx source directory not found at $(NGINX_DIR)$(COLOR_RESET)"; \
		echo "Please download and extract nginx source, then run:"; \
		echo "  make config NGINX_DIR=/path/to/nginx-source"; \
		exit 1; \
	fi
	@if [ -f "$(NGINX_DIR)/configure" ]; then \
		echo "$(COLOR_BLUE)Using nginx tarball source (./configure)$(COLOR_RESET)"; \
		cd $(NGINX_DIR) && ./configure --add-dynamic-module=$(MODULE_DIR); \
	elif [ -f "$(NGINX_DIR)/auto/configure" ]; then \
		echo "$(COLOR_BLUE)Using nginx GitHub source (auto/configure)$(COLOR_RESET)"; \
		cd $(NGINX_DIR) && auto/configure --add-dynamic-module=$(MODULE_DIR); \
	else \
		echo "$(COLOR_YELLOW)ERROR: Cannot find configure script!$(COLOR_RESET)"; \
		echo "Neither ./configure nor auto/configure found in $(NGINX_DIR)"; \
		echo "Please ensure you have valid nginx source code."; \
		exit 1; \
	fi
	@echo "$(COLOR_GREEN)Configuration complete!$(COLOR_RESET)"

build:
	@echo "$(COLOR_GREEN)Building hijinx module...$(COLOR_RESET)"
	@if [ ! -d "$(NGINX_DIR)" ]; then \
		echo "$(COLOR_YELLOW)Nginx source directory not found. Run 'make config' first.$(COLOR_RESET)"; \
		exit 1; \
	fi
	@cd $(NGINX_DIR) && make modules
	@echo "$(COLOR_GREEN)Build complete!$(COLOR_RESET)"
	@echo "Module location: $(NGINX_DIR)/objs/ngx_http_hijinx_module.so"

install:
	@echo "$(COLOR_GREEN)Installing hijinx module...$(COLOR_RESET)"
	@if [ ! -f "$(NGINX_DIR)/objs/ngx_http_hijinx_module.so" ]; then \
		echo "$(COLOR_YELLOW)Module not found. Run 'make build' first.$(COLOR_RESET)"; \
		exit 1; \
	fi
	@sudo mkdir -p $(INSTALL_DIR)
	@sudo cp $(NGINX_DIR)/objs/ngx_http_hijinx_module.so $(INSTALL_DIR)/
	@echo "$(COLOR_GREEN)Module copied to $(INSTALL_DIR)/$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BLUE)Installing module configuration...$(COLOR_RESET)"
	@sudo mkdir -p /usr/share/nginx/modules-available 2>/dev/null || true
	@sudo mkdir -p /etc/nginx/modules-enabled 2>/dev/null || true
	@sudo cp mod_http_hijinx.conf /usr/share/nginx/modules-available/
	@sudo chmod 644 /usr/share/nginx/modules-available/mod_http_hijinx.conf
	@echo "$(COLOR_GREEN)Module config installed to /usr/share/nginx/modules-available/$(COLOR_RESET)"
	@if [ ! -L /etc/nginx/modules-enabled/50-mod-http-hijinx.conf ]; then \
		if [ -e /etc/nginx/modules-enabled/50-mod-http-hijinx.conf ]; then \
			echo "$(COLOR_YELLOW)Regular file exists at /etc/nginx/modules-enabled/50-mod-http-hijinx.conf, removing...$(COLOR_RESET)"; \
			sudo rm /etc/nginx/modules-enabled/50-mod-http-hijinx.conf; \
		fi; \
		sudo ln -s /usr/share/nginx/modules-available/mod_http_hijinx.conf /etc/nginx/modules-enabled/50-mod-http-hijinx.conf 2>/dev/null && \
			echo "$(COLOR_GREEN)Module enabled via symlink in modules-enabled/$(COLOR_RESET)" || \
			echo "$(COLOR_YELLOW)Could not create symlink (may need manual setup)$(COLOR_RESET)"; \
	else \
		LINK_TARGET=$$(readlink /etc/nginx/modules-enabled/50-mod-http-hijinx.conf); \
		if [ "$$LINK_TARGET" = "/usr/share/nginx/modules-available/mod_http_hijinx.conf" ]; then \
			echo "$(COLOR_GREEN)Symlink already exists and is correct$(COLOR_RESET)"; \
		else \
			echo "$(COLOR_YELLOW)Symlink exists but points to $$LINK_TARGET$(COLOR_RESET)"; \
			echo "$(COLOR_YELLOW)Updating symlink to point to /usr/share/nginx/modules-available/mod_http_hijinx.conf$(COLOR_RESET)"; \
			sudo rm /etc/nginx/modules-enabled/50-mod-http-hijinx.conf; \
			sudo ln -s /usr/share/nginx/modules-available/mod_http_hijinx.conf /etc/nginx/modules-enabled/50-mod-http-hijinx.conf; \
			echo "$(COLOR_GREEN)Symlink updated$(COLOR_RESET)"; \
		fi; \
	fi
	@echo ""
	@echo "$(COLOR_BLUE)Installing logrotate configuration...$(COLOR_RESET)"
	@sudo cp logrotate-hijinx.conf /etc/logrotate.d/hijinx 2>/dev/null && \
		sudo chmod 644 /etc/logrotate.d/hijinx && \
		echo "$(COLOR_GREEN)Logrotate configuration installed!$(COLOR_RESET)" || \
		echo "$(COLOR_YELLOW)Logrotate not found or failed to install config$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_BLUE)Module installation complete!$(COLOR_RESET)"
	@echo "  Binary: $(INSTALL_DIR)/ngx_http_hijinx_module.so"
	@echo "  Config: /usr/share/nginx/modules-available/mod_http_hijinx.conf"
	@echo "  Symlink: /etc/nginx/modules-enabled/50-mod-http-hijinx.conf"
	@echo ""
	@echo "$(COLOR_BLUE)Next steps:$(COLOR_RESET)"
	@echo "1. Add to nginx.conf (top level): include /etc/nginx/modules-enabled/*.conf;"
	@echo "2. Configure hijinx in http block (see /etc/nginx/hijinx/hijinx-nginx.conf)"
	@echo "3. Test config: sudo nginx -t"
	@echo "4. Reload nginx: sudo systemctl reload nginx"

test:
	@echo "$(COLOR_GREEN)Testing nginx configuration...$(COLOR_RESET)"
	@sudo nginx -t

logrotate:
	@echo "$(COLOR_GREEN)Installing logrotate configuration...$(COLOR_RESET)"
	@if [ ! -f "logrotate-hijinx.conf" ]; then \
		echo "$(COLOR_YELLOW)logrotate-hijinx.conf not found$(COLOR_RESET)"; \
		exit 1; \
	fi
	@sudo cp logrotate-hijinx.conf /etc/logrotate.d/hijinx
	@sudo chmod 644 /etc/logrotate.d/hijinx
	@echo "$(COLOR_GREEN)Logrotate configuration installed!$(COLOR_RESET)"
	@echo "Test with: sudo logrotate -d /etc/logrotate.d/hijinx"

enable:
	@echo "$(COLOR_GREEN)Enabling hijinx module...$(COLOR_RESET)"
	@if [ ! -f /etc/nginx/modules-available/mod_http_hijinx.conf ]; then \
		echo "$(COLOR_YELLOW)Module config not found. Run 'make install' first.$(COLOR_RESET)"; \
		exit 1; \
	fi
	@sudo mkdir -p /etc/nginx/modules-enabled
	@sudo ln -sf /etc/nginx/modules-available/mod_http_hijinx.conf /etc/nginx/modules-enabled/mod_http_hijinx.conf
	@echo "$(COLOR_GREEN)Module enabled!$(COLOR_RESET)"
	@echo "Reload nginx: sudo nginx -s reload"

disable:
	@echo "$(COLOR_GREEN)Disabling hijinx module...$(COLOR_RESET)"
	@sudo rm -f /etc/nginx/modules-enabled/mod_http_hijinx.conf
	@echo "$(COLOR_GREEN)Module disabled!$(COLOR_RESET)"
	@echo "Reload nginx: sudo nginx -s reload"

clean:
	@echo "$(COLOR_GREEN)Cleaning build artifacts...$(COLOR_RESET)"
	@if [ -d "$(NGINX_DIR)" ]; then \
		cd $(NGINX_DIR) && make clean 2>/dev/null || true; \
	fi
	@echo "$(COLOR_GREEN)Clean complete!$(COLOR_RESET)"

all: setup config build install
	@echo "$(COLOR_GREEN)All done! Don't forget to configure nginx and reload.$(COLOR_RESET)"

# Development helpers
dev-setup: setup
	@echo "$(COLOR_GREEN)Creating development environment...$(COLOR_RESET)"
	@mkdir -p dev-logs
	@echo "Development logs will be in: $(MODULE_DIR)/dev-logs"

# Check nginx version
check-nginx:
	@echo "$(COLOR_BLUE)Checking nginx installation...$(COLOR_RESET)"
	@nginx -v 2>&1 || echo "$(COLOR_YELLOW)Nginx not found in PATH$(COLOR_RESET)"
	@which nginx || echo "$(COLOR_YELLOW)Nginx binary not found$(COLOR_RESET)"
