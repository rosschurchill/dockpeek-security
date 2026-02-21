# DockPeek Security — Sprint Plan
**Date**: 2026-02-21
**Version target**: 1.1.0

---

## Sprint Goals

Three parallel workstreams to ship in one sprint:

| # | Workstream | Owner Agent | Priority |
|---|-----------|-------------|----------|
| 1 | **Fix stuck CVE scanner** | Backend Engineer | HIGH — blocking UX |
| 2 | **UI/UX dashboard overhaul** | Frontend Engineer | HIGH — user visible |
| 3 | **Orchestration label system** | Backend Engineer | MEDIUM — new feature |

---

## Workstream 1: Fix Stuck CVE Scanner

### Problem
The background Trivy scanner processes images **one at a time**. Private registry images
(e.g. `registry.theshellnet.com/...`) can't be pulled by Trivy and each timeout after 150s,
blocking the entire queue. With ~44 containers, a queue of failed private images means
public images never get scanned. Containers show "scanning..." indefinitely.

### Root Cause
- `_scanner_loop` in `trivy_utils.py` is single-threaded sequential
- No "failed" state — timed-out images get re-queued on every refresh cycle
- UI shows identical `---` for "not yet queued", "pending", and "timed out"

### Solution

**1. Parallel scanner workers** (`trivy_utils.py`)
- Replace single thread with `ThreadPoolExecutor(max_workers=3)`
- Configurable via `TRIVY_SCAN_WORKERS` env var (default: 3)
- Dispatcher thread reads queue, submits to executor

**2. Cache failed scans** (`trivy_utils.py`)
- On timeout or non-zero exit code → store `ScanResult(error="scan_timeout")` in cache
- Prevents same image re-queuing on every background refresh
- Failed results use a short TTL (1 hour, then retry)

**3. Skip failed in auto-queue** (`trivy_utils.py`)
- `queue_auto_scan` already skips `scanned` and `skipped`
- Add `failed` to the skip list

**4. Expose `failed` status** (`get_data.py`)
- `get_vulnerability_summary()` returns `{'scan_status': 'failed'}` when `cached.error` is set

**5. Render failed state in UI** (`cell-renderer.js`)
- `scan_status === 'failed'` → show small `×` with tooltip "Scan failed – image may be inaccessible"

### Files
| File | Change |
|------|--------|
| `dockpeek/dockpeek/trivy_utils.py` | Parallel executor + failed caching |
| `dockpeek/dockpeek/get_data.py` | Expose `failed` scan status |
| `dockpeek/dockpeek/static/js/modules/cell-renderer.js` | Render `failed` state |

---

## Workstream 2: UI/UX Dashboard Overhaul

### Problem
- Security CVE badges are vivid/harsh (bright red, orange, cyan, blue)
- All-zero containers show grey dashes — should show calm green to signal "clean"
- Overall dashboard needs a polish pass using design system principles

### Solution

**1. Run ui-ux-pro-max design system**
- Query: `"security dashboard dark mode monitoring professional"`
- Get palette, typography, spacing, and style recommendations

**2. CVE badge color system** (`styles.css`)
- `vuln-zero` (all zeros) → soft green background matching the "Low" summary chip at top
- Individual severity colors toned down — less saturated, more professional
- Exact targets:
  - Critical: `#7f1d1d` bg, `#fca5a5` text (dark red, not bright)
  - High: `#78350f` bg, `#fcd34d` text (dark amber)
  - Medium: `#164e63` bg, `#67e8f9` text (dark cyan)
  - Low: `#1e3a5f` bg, `#93c5fd` text (dark blue)
  - Zero/clean: `#14532d` bg, `#86efac` text (muted green)

**3. All-green when clean** (`cell-renderer.js`)
- When `total === 0`: render all 4 badges with `vuln-clean` class instead of `vuln-zero`
- This gives positive visual feedback — clean container = all green

**4. Overall dashboard polish** (`styles.css`, `index.html`)
- Row hover states more subtle
- Header button refinements
- Consistency pass on spacing and font sizes

### Files
| File | Change |
|------|--------|
| `dockpeek/dockpeek/static/css/styles.css` | Badge colors, clean state, polish |
| `dockpeek/dockpeek/static/js/modules/cell-renderer.js` | All-green logic for zero CVEs |
| `dockpeek/dockpeek/static/js/modules/security-dashboard.js` | Top summary panel colors |

---

## Workstream 3: Orchestration Label System (Phase 1)

### Problem
Docker stacks have dependency chains (VPN anchor → app dependents). DockPeek currently
has no awareness of these relationships. Updating a `gluetun` container silently breaks
all containers sharing its network namespace.

### Solution (Phase 1 — read & display only, no update execution)

**Label schema** (read from container labels):
```
dockpeek.role         = anchor | dependent | standalone
dockpeek.anchor       = <container-name>     (on dependents)
dockpeek.anchor-type  = network | database | service
dockpeek.stack        = <logical-stack-name>
dockpeek.hide         = true | false
```

**1. Read labels in `get_data.py`**
- Extract all `dockpeek.*` labels from each container
- Add `orchestration` dict to container data:
  ```python
  {
    'role': 'anchor',           # or 'dependent', 'standalone', None
    'anchor': None,             # container name of anchor (for dependents)
    'anchor_type': 'network',   # network / database / service
    'dependents': ['sonarr', 'radarr'],  # populated server-side for anchors
    'stack_override': 'arr',    # dockpeek.stack label if set
    'hidden': False
  }
  ```

**2. Hide support**
- If `dockpeek.hide=true`, exclude container from the list entirely

**3. Stack column**
- If `dockpeek.stack` label is set, use it as the stack name (overrides compose project)

**4. UI indicators** (`cell-renderer.js`, `styles.css`)
- Anchor containers: small chain-link icon (⛓ as SVG) next to name
- Dependent containers: small indent indicator + tooltip "Depends on: gluetun (network)"
- Update arrow for anchors: amber warning colour + tooltip "Updating will affect N dependents"

**5. No destructive actions** — Phase 1 is read-only. The update orchestration playbooks
(stop dependents → update anchor → recreate dependents) are Phase 2.

### Files
| File | Change |
|------|--------|
| `dockpeek/dockpeek/get_data.py` | Read labels, build orchestration metadata, hide support |
| `dockpeek/dockpeek/static/js/modules/cell-renderer.js` | Role indicators, anchor warning on update arrow |
| `dockpeek/dockpeek/static/css/styles.css` | Orchestration badge styles |

---

## Versioning

After all three workstreams complete:
- Bump `dockpeek/docker-compose.yml` image tag to `1.1.0`
- Update `README.md` feature table
- Build + push image to `registry.theshellnet.com/dockpeek-security:1.1.0`
- Update Portainer stack via API

---

## Open Questions (Orchestration Phase 2)

1. **Portainer vs Docker direct**: Update via Portainer API or raw Docker SDK?
2. **env files**: How to pass stack env vars when recreating containers?
3. **Health check fallback**: TCP port probe if no HEALTHCHECK defined?
4. **ntfy notifications**: Alert when anchor update triggers chain restart?
5. **Dry-run mode**: Show user what will be affected before executing?
6. **Rollback**: If dependent fails health check post-update, revert anchor?
