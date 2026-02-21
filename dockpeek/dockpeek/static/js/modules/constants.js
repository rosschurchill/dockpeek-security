export const UPTIME_UNITS = [
  { name: 'year', divisor: 365 * 24 * 60 },
  { name: 'month', divisor: 30 * 24 * 60 },
  { name: 'week', divisor: 7 * 24 * 60 },
  { name: 'day', divisor: 24 * 60 },
  { name: 'hour', divisor: 60 },
  { name: 'minute', divisor: 1 }
];

export const STATUS_CLASSES = {
  running: 'status-running',
  healthy: 'status-healthy',
  unhealthy: 'status-unhealthy',
  starting: 'status-starting',
  exited: 'status-exited',
  paused: 'status-paused',
  restarting: 'status-restarting',
  removing: 'status-removing',
  dead: 'status-dead',
  created: 'status-created'
};

export const EXIT_CODE_MESSAGES = {
  0: 'normal',
  1: 'General application error',
  2: 'Misuse of shell command',
  125: 'Docker daemon error',
  126: 'Container command not executable',
  127: 'Container command not found',
  128: 'Invalid exit argument',
  130: 'SIGINT - interrupted',
  134: 'SIGABRT - aborted',
  137: 'SIGKILL - killed',
  139: 'SIGSEGV - segmentation fault',
  143: 'SIGTERM - terminated'
};

export const COLUMN_MAPPINGS = {
  name: { selector: '[data-sort-column="name"]', cellClass: 'table-cell-name' },
  server: { selector: '.server-column', cellClass: 'table-cell-server' },
  stack: { selector: '[data-sort-column="stack"]', cellClass: 'table-cell-stack' },
  network: { selector: '[data-sort-column="network"]', cellClass: 'table-cell-network' },
  ip: { selector: '[data-sort-column="ip"]', cellClass: 'table-cell-ip' },
  image: { selector: '[data-sort-column="image"]', cellClass: 'table-cell-image' },
  tags: { selector: '[data-sort-column="tags"]', cellClass: 'table-cell-tags' },
  security: { selector: '[data-sort-column="security"]', cellClass: 'table-cell-security' },
  status: { selector: '[data-sort-column="status"]', cellClass: 'table-cell-status' },
  ports: { selector: '[data-sort-column="ports"]', cellClass: 'table-cell-ports' },
  traefik: { selector: '.traefik-column', cellClass: 'table-cell-traefik' },
  logs: { selector: '[data-sort-column="logs"]', cellClass: 'table-cell-logs' }
};
