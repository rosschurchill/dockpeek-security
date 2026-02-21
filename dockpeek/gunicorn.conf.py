import os

workers = int(os.environ.get('WORKERS', '2'))

worker_class = 'gevent'
worker_connections = 1024
port = int(os.environ.get('PORT', '8000'))
bind = f'0.0.0.0:{port}'

# Timeouts
timeout = 600
graceful_timeout = 30
keepalive = 30

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'warning'

# Performance
sendfile = False
backlog = 2048
max_requests = 2000 
max_requests_jitter = 100

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190


# --- ASCII Art ---
def get_dockpeek_art():
    version = os.environ.get('VERSION', 'dev')
    return f"""
══ Gunicorn Configuration:
-- Workers: {workers} ({worker_class})
-- Bind: {bind}
-- Timeout: {timeout}s | Graceful: {graceful_timeout}s | Keepalive: {keepalive}s
-- Worker connections: {worker_connections} | Backlog: {backlog}
-- Max requests: {max_requests} ±{max_requests_jitter}
--  
--     _         _               _   
--   _| |___ ___| |_ ___ ___ ___| |_ 
--  | . | . |  _| '_| . | -_| -_| '_|
--  |___|___|___|_|_|  _|___|___|_|_|
--                  |_|              
--                                                               
══ Version: {version}                
══ https://github.com/dockpeek/dockpeek  
--
══ To support dev visit:
══ https://buymeacoffee.com/dockpeek
 

"""

# --- Server Hooks ---
def when_ready(server):
    print(get_dockpeek_art())
    server.log.info("Gunicorn server is ready. Spawning workers...")


def worker_exit(server, worker):
    server.log.info(f"Worker {worker.pid} exited")

def worker_abort(worker):
    worker.log.warning(f"Worker {worker.pid} aborted")

def on_exit(server):
    server.log.warning("Shutting down Gunicorn")
