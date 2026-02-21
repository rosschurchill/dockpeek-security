export const state = {
  allContainersData: [],
  allServersData: [],
  serverStatusCache: {
    data: null,
    timestamp: 0,
    ttl: 30000
  },
  filteredAndSortedContainers: [],
  swarmServers: [],
  pruneInfoCache: null,
  currentSortColumn: "name",
  currentSortDirection: "asc",
  currentServerFilter: "all",
  isDataLoaded: false,
  isCheckingForUpdates: false,
  updateCheckController: null,
  // Trivy security scanning state
  trivyEnabled: false,
  trivyHealthy: false,
  groupByStack: false,
  statusFilter: null,  // 'running'|'stopped'|'unhealthy'|'paused'|'other'|'stacked'|null
  columnOrder: ['name', 'stack', 'server', 'network', 'ip', 'ports', 'traefik', 'image', 'tags', 'security', 'logs', 'status'],
  columnVisibility: {
    name: true,
    server: true,
    stack: true,
    network: false,  // Hidden by default
    ip: false,       // Hidden by default
    image: true,
    tags: true,
    security: true,  // Shown by default for security focus
    status: true,
    ports: true,
    traefik: true,
    logs: true
  }
};
