# DockPeek Security Edition - Project Plan

## Project Vision

Transform DockPeek from a simple Docker dashboard into the **ultimate Docker maintenance and security platform** by integrating Trivy vulnerability scanning, intelligent version checking, and comprehensive security monitoring.

---

## Current Status: v1.7.2 Security Edition

### Completed Features

#### Core Security Integration

| Feature | Status | Description |
|---------|--------|-------------|
| Trivy CVE Scanning | Complete | Real-time vulnerability scanning via Trivy server |
| Vulnerability Dashboard | Complete | Traffic-light style severity display (C/H/M/L) |
| Auto-Scan on Load | Complete | Automatically scans unscanned images in background |
| Scan History | Complete | SQLite-based historical tracking of vulnerabilities |
| Security Trends | Complete | Track improving/degrading security posture over time |
| New Vulnerability Alerts | Complete | Detect newly discovered CVEs in last 24h |

#### Version Management

| Feature | Status | Description |
|---------|--------|-------------|
| Registry Version Checker | Complete | Query Docker registries for newer tags |
| Semantic Version Comparison | Complete | Intelligent version parsing (semver, date-based, etc.) |
| New Version Indicators | Complete | Green arrow icons for available upgrades |
| One-Click Upgrades | Complete | Upgrade to specific versions from UI |
| Version History Cache | Complete | File-based cache shared across workers |

#### Infrastructure Improvements

| Feature | Status | Description |
|---------|--------|-------------|
| Multi-Worker Caching | Complete | File-based caches with fcntl locking |
| Background Scheduler | Complete | Single-scheduler guard for Gunicorn workers |
| Shared Cache System | Complete | Generic FileBasedCache class for all caches |
| Image Pruning | Complete | Clean up unused images with pending-update protection |

#### SIEM & Monitoring Integration

| Feature | Status | Description |
|---------|--------|-------------|
| Prometheus Metrics | Complete | `/metrics` endpoint for Grafana dashboards |
| Per-Container Metrics | Complete | Vulnerability counts by container/server/image |
| ntfy Notifications | Complete | Real-time alerts for critical/high CVEs |
| Alert Thresholds | Complete | Configurable critical/high minimums |
| Cooldown System | Complete | Prevents notification spam (default 60 min) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DockPeek Security                         │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (JavaScript Modules)                                   │
│  ├── cell-renderer.js      - Vulnerability badges, version icons│
│  ├── security-dashboard.js - CVE detail modals                  │
│  ├── version-check.js      - Version selection UI               │
│  └── data-fetch.js         - API communication                  │
├─────────────────────────────────────────────────────────────────┤
│  Backend (Flask/Gunicorn)                                        │
│  ├── main.py               - REST API endpoints                 │
│  ├── trivy_utils.py        - Trivy integration & caching        │
│  ├── version_checker.py    - Registry queries & comparison      │
│  ├── scan_history.py       - SQLite vulnerability history       │
│  ├── background_scheduler.py - Periodic refresh tasks           │
│  ├── shared_cache.py       - Multi-worker safe caching          │
│  ├── metrics.py            - Prometheus metrics endpoint        │
│  └── notifications.py      - ntfy alert integration             │
├─────────────────────────────────────────────────────────────────┤
│  External Services                                               │
│  ├── Docker API            - Container/image management         │
│  ├── Trivy Server          - CVE scanning (via docker exec)     │
│  ├── Docker Registries     - Version tag queries                │
│  ├── Traefik API           - Route discovery (optional)         │
│  ├── Prometheus            - Metrics scraping                   │
│  └── ntfy                  - Security alert notifications       │
├─────────────────────────────────────────────────────────────────┤
│  Monitoring Stack Integration                                    │
│  ├── Prometheus ← /metrics - Scrapes vulnerability counts       │
│  ├── Grafana               - Dashboard visualization            │
│  └── ntfy ← alerts         - Real-time security notifications   │
└─────────────────────────────────────────────────────────────────┘
```

---

## File-Based Cache Architecture

All caches use fcntl locking for multi-worker safety:

| Cache | File Location | Duration | Purpose |
|-------|---------------|----------|---------|
| Version Cache | `/tmp/dockpeek_version_cache.json` | 1 hour | Registry version queries |
| Trivy Cache | `/tmp/dockpeek_trivy_cache.json` | 1 hour | CVE scan results |
| Update Cache | `/tmp/dockpeek_update_cache.json` | 2 min | Image pull comparisons |
| Scheduler Lock | `/tmp/dockpeek_scheduler.lock` | Process lifetime | Single scheduler guard |

---

## API Endpoints

### Security APIs

```
GET  /api/security/status          - Trivy integration status
POST /api/scan/<image>             - Trigger vulnerability scan
GET  /api/vulnerabilities/<image>  - Get cached scan results
GET  /api/security/summary         - Aggregate vulnerability counts
GET  /api/security/history/<image> - Scan history for image
GET  /api/security/new-vulnerabilities - Recently discovered CVEs
GET  /api/security/trends          - Security posture trends
GET  /api/security/stats           - Database statistics
POST /api/security/cache/clear     - Clear scan cache
```

### Version APIs

```
GET  /api/version/check/<image>    - Check for newer version
GET  /api/version/list/<image>     - List available versions
POST /api/version/check-all        - Check all containers
```

### Container Management APIs

```
GET  /data                         - All container data with security info
POST /check-updates                - Pull-based update check
POST /update-container             - Upgrade container to new image
POST /get-prune-info               - Get unused image info
POST /prune-images                 - Remove unused images
```

### Monitoring & Notification APIs

```
GET  /metrics                      - Prometheus metrics (no auth required)
GET  /api/notifications/status     - Check ntfy configuration
POST /api/notifications/test       - Send test notification
```

**Prometheus Metrics Exposed:**
```
dockpeek_vulnerabilities_critical_total
dockpeek_vulnerabilities_high_total
dockpeek_vulnerabilities_medium_total
dockpeek_vulnerabilities_low_total
dockpeek_vulnerabilities_total
dockpeek_containers_total
dockpeek_containers_running
dockpeek_containers_scanned
dockpeek_containers_unscanned
dockpeek_trivy_healthy
dockpeek_scans_pending
dockpeek_container_vulnerabilities{container,server,image,severity}
```

---

## Deployment Configuration

### Docker Compose with Full SIEM Integration

```yaml
services:
  dockpeek:
    image: dockpeek/dockpeek:latest
    container_name: dockpeek
    environment:
      - SECRET_KEY=your_secure_secret_key
      - USERNAME=admin
      - PASSWORD=admin
      # Security Features
      - TRIVY_SERVER_URL=http://trivy-server:4954
      - TRIVY_CONTAINER_NAME=trivy-server
      - SCAN_HISTORY_ENABLED=true
      - BACKGROUND_REFRESH_ENABLED=true
      - BACKGROUND_REFRESH_INTERVAL=300
      - VERSION_CHECK_INTERVAL=3600
      # SIEM Integration
      - NTFY_URL=http://ntfy:80
      - NTFY_TOPIC=security-alerts
      - NTFY_COOLDOWN_MINUTES=60
      - NTFY_MIN_CRITICAL=1
      - NTFY_MIN_HIGH=10
    ports:
      - "5051:8000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - dockpeek_data:/data
    networks:
      - monitoring
    depends_on:
      - trivy-server

  trivy-server:
    image: aquasec/trivy:latest
    container_name: trivy-server
    command: ["server", "--listen", "0.0.0.0:4954"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - trivy_cache:/root/.cache/trivy
    networks:
      - monitoring

volumes:
  dockpeek_data:
  trivy_cache:

networks:
  monitoring:
    external: true  # Connect to existing monitoring stack
```

### Prometheus Scrape Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'dockpeek'
    static_configs:
      - targets: ['dockpeek:8000']
    metrics_path: /metrics
    scrape_interval: 60s
```

---

## Roadmap

### Phase 1: Core Security (Complete)
- [x] Trivy integration via Docker exec
- [x] CVE scanning with caching
- [x] Vulnerability summary display
- [x] Traffic-light severity badges

### Phase 2: Version Intelligence (Complete)
- [x] Registry version queries
- [x] Semantic version comparison
- [x] New version indicators in UI
- [x] One-click version upgrades

### Phase 3: Historical Tracking (Complete)
- [x] SQLite scan history database
- [x] Vulnerability trends over time
- [x] New vulnerability detection
- [x] Security posture monitoring

### Phase 4: Multi-Worker Stability (Complete)
- [x] File-based caching with fcntl
- [x] Single scheduler guard
- [x] Cross-worker data sharing
- [x] Background refresh system

### Phase 5: SIEM Integration (Complete)
- [x] Prometheus metrics endpoint (`/metrics`)
- [x] Per-container vulnerability metrics
- [x] ntfy notification integration
- [x] Configurable alert thresholds
- [x] Cooldown to prevent alert spam

### Phase 6: Future Enhancements (Planned)
- [ ] Docker system info dashboard (disk, memory, CPU)
- [ ] Container resource monitoring
- [ ] Volume management panel
- [ ] Notification webhooks (ntfy, Discord, Slack)
- [ ] Custom security policies
- [ ] SBOM generation
- [ ] Compliance reporting

---

## Environment Variables

### Security Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TRIVY_SERVER_URL` | - | Trivy server URL (enables scanning) |
| `TRIVY_CONTAINER_NAME` | `trivy` | Container name for docker exec |
| `SCAN_HISTORY_ENABLED` | `true` | Enable SQLite scan history |
| `SCAN_HISTORY_DB` | `/data/scan_history.db` | History database path |
| `TRIVY_CACHE_DURATION` | `3600` | Scan cache duration (seconds) |

### Background Scheduler

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKGROUND_REFRESH_ENABLED` | `true` | Enable background scheduler |
| `BACKGROUND_REFRESH_INTERVAL` | `300` | CVE refresh interval (seconds) |
| `VERSION_CHECK_INTERVAL` | `3600` | Version check interval (seconds) |

### Cache Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKPEEK_VERSION_CACHE` | `/tmp/dockpeek_version_cache.json` | Version cache file |
| `DOCKPEEK_TRIVY_CACHE` | `/tmp/dockpeek_trivy_cache.json` | Trivy cache file |
| `DOCKPEEK_UPDATE_CACHE` | `/tmp/dockpeek_update_cache.json` | Update cache file |

### ntfy Notifications

| Variable | Default | Description |
|----------|---------|-------------|
| `NTFY_URL` | - | ntfy server URL (required to enable) |
| `NTFY_TOPIC` | `security-alerts` | Topic for security alerts |
| `NTFY_ENABLED` | `true` | Enable/disable notifications |
| `NTFY_COOLDOWN_MINUTES` | `60` | Minimum time between alerts |
| `NTFY_MIN_CRITICAL` | `1` | Alert if critical CVEs >= this |
| `NTFY_MIN_HIGH` | `10` | Alert if high CVEs >= this |

---

## Contributing

This project combines the excellent DockPeek dashboard with enterprise-grade security features. Contributions welcome for:

- Additional registry support
- New security integrations
- UI/UX improvements
- Documentation

---

## Credits

- **DockPeek** - Original dashboard framework
- **Trivy** - Vulnerability scanning engine by Aqua Security
- **Claude AI** - Development assistance and architecture design

---

*Last Updated: January 2026*
