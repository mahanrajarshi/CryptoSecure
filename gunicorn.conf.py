import os
import multiprocessing

# Dynamic worker count based on available CPUs (better for cloud deployment)
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = 'gevent'

# Use PORT environment variable provided by Render
bind = f"0.0.0.0:{os.environ.get('PORT', 5000)}"
timeout = 120
keepalive = 5
preload_app = True

# Security settings
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
