import os
import multiprocessing

# ============================================
# GUNICORN CONFIG - FREE TIER OPTIMIZED
# ============================================

# Bind to Render's PORT environment variable
port = os.environ.get('PORT', '5000')
bind = f"0.0.0.0:{port}"

# Worker Configuration
# 2 workers = tối ưu cho free tier (đủ cho 100-200 concurrent users)
workers = 2
worker_class = 'sync'
threads = 1

# Connection Settings
worker_connections = 100
backlog = 100
max_requests = 500  # Restart worker sau 500 requests để tránh memory leak
max_requests_jitter = 50  # Random jitter

# Timeout Settings
timeout = 60  # 60s cho upload ảnh
graceful_timeout = 30
keepalive = 5

# Logging
accesslog = '-'  # stdout
errorlog = '-'   # stderr
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sµs'

# Process Naming
proc_name = 'memorybox_web'

# Server Mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# ============================================
# CALLBACKS - Monitoring & Logging
# ============================================

def on_starting(server):
    """Called just before master process initialization"""
    server.log.info("=" * 60)
    server.log.info("🚀 MEMORYBOX - Starting Gunicorn Server")
    server.log.info("=" * 60)
    server.log.info(f"📊 Configuration:")
    server.log.info(f"   Workers: {workers}")
    server.log.info(f"   Worker Class: {worker_class}")
    server.log.info(f"   Bind: {bind}")
    server.log.info(f"   Timeout: {timeout}s")
    server.log.info(f"   Max Requests: {max_requests}")
    server.log.info(f"   Python: {os.sys.version.split()[0]}")
    server.log.info("=" * 60)

def when_ready(server):
    """Called just after server starts"""
    server.log.info("✅ Server ready - Accepting connections")
    server.log.info(f"🌐 Health check: http://localhost:{port}/health")

def on_reload(server):
    """Called during reload via SIGHUP"""
    server.log.info("🔄 Reloading workers...")

def pre_fork(server, worker):
    """Called before worker fork"""
    pass

def post_fork(server, worker):
    """Called after worker fork"""
    server.log.info(f"✨ Worker spawned (pid: {worker.pid})")

def post_worker_init(worker):
    """Called after worker initialization"""
    worker.log.info(f"🎉 Worker initialized (pid: {worker.pid})")

def worker_int(worker):
    """Called on SIGINT/SIGQUIT"""
    worker.log.warning(f"⚠️  Worker received interrupt (pid: {worker.pid})")

def worker_abort(worker):
    """Called on SIGABRT - usually timeout"""
    worker.log.error(f"❌ Worker aborted - timeout or crash (pid: {worker.pid})")
    worker.log.error(f"   Check if requests are taking > {timeout}s")

def pre_exec(server):
    """Called before new master fork"""
    server.log.info("🔄 Forking new master process")

def pre_request(worker, req):
    """Called before processing request"""
    # Uncomment for detailed request logging
    # worker.log.debug(f"→ {req.method} {req.path}")
    pass

def post_request(worker, req, environ, resp):
    """Called after processing request"""
    # Uncomment for detailed response logging
    # worker.log.debug(f"← {req.method} {req.path} - {resp.status}")
    pass

def worker_exit(server, worker):
    """Called when worker exits"""
    server.log.info(f"👋 Worker exited (pid: {worker.pid})")

def nworkers_changed(server, new_value, old_value):
    """Called when worker count changes"""
    server.log.info(f"👥 Workers changed: {old_value} → {new_value}")

def on_exit(server):
    """Called before master exit"""
    server.log.info("=" * 60)
    server.log.info("🛑 Shutting down MemoryBox server")
    server.log.info("👋 Goodbye!")
    server.log.info("=" * 60)


# ============================================
# ALTERNATIVE CONFIGS (Comment/Uncomment)
# ============================================

# --- CONFIG A: Minimal (Testing/Development) ---
# workers = 1
# timeout = 30
# max_requests = 100

# --- CONFIG B: Current (Production - 50-200 users) ---
# (Already configured above)

# --- CONFIG C: High Load (200+ users) - Requires upgrade ---
# workers = 4
# worker_class = 'gevent'
# worker_connections = 200
# timeout = 90
# max_requests = 1000