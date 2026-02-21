# DockPeek Security

A security-focused fork of [DockPeek](https://github.com/dockpeek/dockpeek) — a lightweight, self-hosted Docker dashboard — extended with CVE scanning, version intelligence, and production-grade multi-worker support.

## What's Different

This fork adds a full security and observability stack on top of the original DockPeek:

| Feature | Original DockPeek | DockPeek Security |
|---|---|---|
| Container dashboard | ✅ | ✅ |
| Multi-host support | ✅ | ✅ |
| Traefik routes | ✅ | ✅ |
| Image update checks | ✅ | ✅ |
| **CVE vulnerability scanning** | ❌ | ✅ Trivy integration |
| **Background CVE refresh** | ❌ | ✅ Scheduled with app context |
| **Semver version checking** | ❌ | ✅ Word-boundary unstable filter |
| **Prometheus metrics** | ❌ | ✅ /metrics endpoint |
| **Security notifications** | ❌ | ✅ Bell icon + ntfy alerts |
| **Scan history database** | ❌ | ✅ SQLite scan tracking |
| **Multi-worker safe cache** | ❌ | ✅ File-based shared cache |
| **Duplicate container fix** | ❌ | ✅ Compose label preservation |
| **Page visibility polling** | ❌ | ✅ Pauses when tab hidden |

## Quick Start

```yaml
services:
  dockpeek:
    image: registry.theshellnet.com/dockpeek-security:1.0.3
    container_name: dockpeek-security
    restart: unless-stopped
    ports:
      - "5051:8000"
    environment:
      - SECRET_KEY=your_secure_secret_key_here
      - DISABLE_AUTH=true
      - BACKGROUND_REFRESH_ENABLED=true
      - BACKGROUND_REFRESH_INTERVAL=300
      - VERSION_CHECK_INTERVAL=3600
      - TRIVY_SERVER_URL=http://trivy:4954
      - TRIVY_CONTAINER_NAME=trivy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - trivy

  trivy:
    image: aquasec/trivy:0.58.0
    container_name: trivy
    restart: unless-stopped
    command: server --listen 0.0.0.0:4954
    volumes:
      - trivy-cache:/root/.cache/trivy

volumes:
  trivy-cache:
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | required | Flask secret key |
| `DISABLE_AUTH` | `false` | Disable login (set `true` for trusted networks) |
| `BACKGROUND_REFRESH_ENABLED` | `true` | Enable background CVE refresh |
| `BACKGROUND_REFRESH_INTERVAL` | `300` | CVE refresh interval (seconds) |
| `VERSION_CHECK_INTERVAL` | `3600` | Version check interval (seconds) |
| `TRIVY_SERVER_URL` | — | Trivy server URL for CVE scanning |
| `TRIVY_CONTAINER_NAME` | `trivy-server` | Trivy container name for exec |
| `TRIVY_SCAN_TIMEOUT` | `120` | Per-image scan timeout (seconds) |
| `TRIVY_CACHE_DURATION` | `3600` | Scan result cache TTL (seconds) |

## Credits

Built on [DockPeek](https://github.com/dockpeek/dockpeek) by the DockPeek contributors — MIT Licensed.

CVE scanning powered by [Trivy](https://github.com/aquasecurity/trivy) by Aqua Security.
