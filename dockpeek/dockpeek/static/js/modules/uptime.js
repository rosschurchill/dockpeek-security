import { UPTIME_UNITS } from './constants.js';

export function calculateUptime(startedAt) {
  if (!startedAt) return '';

  const uptimeMinutes = Math.floor((Date.now() - new Date(startedAt)) / (1000 * 60));

  for (const unit of UPTIME_UNITS) {
    const value = Math.floor(uptimeMinutes / unit.divisor);
    if (value > 0) {
      return value === 1 ? `1 ${unit.name}` : `${value} ${unit.name}s`;
    }
  }

  return 'less than 1 minute';
}
