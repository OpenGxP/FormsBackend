bind = ':8000'
backlog = 2048

workers = 2
worker_class = 'sync'
worker_connections = 1000
timeout = 30
keepalive = 2

spew = False

errorlog = "/data/web/logs/gunicorn_error.log"
accesslog = "/data/web/logs/gunicorn_access.log"

loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
