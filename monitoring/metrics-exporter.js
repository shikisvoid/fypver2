// Prometheus metrics exporter for SDP segment-aware monitoring.

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.METRICS_PORT ? parseInt(process.env.METRICS_PORT, 10) : 9090;

const DEFAULT_LOG_DIR = process.platform === 'win32' ? 'C:\\logs' : '/logs';
const LOG_DIR = process.env.LOG_DIR || DEFAULT_LOG_DIR;
const TELEMETRY_LOG = path.join(LOG_DIR, 'telemetry.log');
const LOG_FILE = path.join(LOG_DIR, 'comprehensive-network-monitor.log');
const ISOLATIONS_FILE = path.join(LOG_DIR, 'isolations.json');
const SPA_CONTROLLER_BASE_URL = process.env.SPA_CONTROLLER_BASE_URL || 'http://spa-controller:7001';
const MAX_JSON_LOG_LINES = process.env.MAX_JSON_LOG_LINES ? parseInt(process.env.MAX_JSON_LOG_LINES, 10) : 2000;
const MAX_TEXT_LOG_LINES = process.env.MAX_TEXT_LOG_LINES ? parseInt(process.env.MAX_TEXT_LOG_LINES, 10) : 1000;
const MAX_TAIL_BYTES = process.env.MAX_TAIL_BYTES ? parseInt(process.env.MAX_TAIL_BYTES, 10) : (1024 * 1024);

const RECENT_TELEMETRY_MAX = 100;
const recentTelemetry = [];

const HOST_SEGMENT_MAP = {
  'hospital-api-gateway': 'edge',
  'external-api-gateway': 'edge',
  'hospital-frontend': 'edge',
  'patient-terminal': 'edge-endpoint',
  'admin-workstation': 'security-endpoint',
  'doctor-workstation': 'security-endpoint',
  'nurse-workstation': 'security-endpoint',
  'receptionist-workstation': 'security-endpoint',
  'labtech-workstation': 'security-endpoint',
  'pharmacist-workstation': 'security-endpoint',
  'accountant-workstation': 'security-endpoint',
  'hospital-iam': 'control',
  'hospital-sdp-controller': 'control',
  'hospital-spa-controller': 'control',
  'spa-controller': 'control',
  'sdp-controller': 'control',
  'hospital-response-controller': 'control',
  'hospital-monitor': 'observability',
  'hospital-prometheus': 'observability',
  'hospital-grafana': 'observability',
  'hospital-ml-engine': 'control',
  'backend-internal-gateway': 'backend-clinical-segment',
  'hospital-backend-internal-gateway': 'backend-clinical-segment',
  'hospital-backend': 'backend-clinical-segment',
  'hospital-encryption': 'backend-support',
  'hospital-db': 'data-private'
};

const metrics = createEmptyMetrics();

try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
} catch (err) {
  console.error(`Failed to create log directory ${LOG_DIR}:`, err.message);
}

function createEmptyMetrics() {
  return {
    isolation_tests_total: 0,
    isolation_tests_passed: 0,
    isolation_tests_failed: 0,
    allowed_connections: 0,
    blocked_attempts: 0,
    security_violations: 0,
    security_score: 100.0,
    telemetry_received: 0,
    last_update: Date.now(),
    segmentTelemetry: new Map(),
    hostTelemetry: new Map(),
    eventTypeTotals: new Map(),
    actionTotals: new Map(),
    isolatedSegments: new Map(),
    gateways: [],
    services: []
  };
}

function normalizeLabel(value, fallback = 'unknown') {
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function escapeLabelValue(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"');
}

function promLine(name, value, labels = null, timestamp = Date.now()) {
  if (labels && Object.keys(labels).length > 0) {
    const serialized = Object.entries(labels)
      .map(([key, labelValue]) => `${key}="${escapeLabelValue(labelValue)}"`)
      .join(',');
    return `${name}{${serialized}} ${value} ${timestamp}`;
  }
  return `${name} ${value} ${timestamp}`;
}

function readTailText(filePath, maxBytes = MAX_TAIL_BYTES) {
  if (!fs.existsSync(filePath)) return '';

  const stats = fs.statSync(filePath);
  if (!stats.size) return '';

  const start = Math.max(0, stats.size - maxBytes);
  const fd = fs.openSync(filePath, 'r');

  try {
    const length = stats.size - start;
    const buffer = Buffer.alloc(length);
    fs.readSync(fd, buffer, 0, length, start);
    let text = buffer.toString('utf8');

    // If we started mid-file, drop the partial first line.
    if (start > 0) {
      const firstNewline = text.indexOf('\n');
      text = firstNewline >= 0 ? text.slice(firstNewline + 1) : '';
    }

    return text;
  } finally {
    fs.closeSync(fd);
  }
}

function readTailLines(filePath, maxLines, maxBytes = MAX_TAIL_BYTES) {
  return readTailText(filePath, maxBytes)
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-maxLines);
}

function readJsonLines(filePath, maxLines = MAX_JSON_LOG_LINES) {
  return readTailLines(filePath, maxLines)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch (err) {
        return null;
      }
    })
    .filter(Boolean);
}

function readJsonFile(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (err) {
    return fallback;
  }
}

function fetchJson(urlString) {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(urlString);
      const req = http.request({
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname + url.search,
        method: 'GET',
        timeout: 3000
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body || '{}'));
          } catch (err) {
            reject(new Error(`Invalid JSON from ${urlString}`));
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Timeout fetching ${urlString}`));
      });
      req.on('error', reject);
      req.end();
    } catch (err) {
      reject(err);
    }
  });
}

function getSegmentMetrics(segment) {
  const key = normalizeLabel(segment);
  if (!metrics.segmentTelemetry.has(key)) {
    metrics.segmentTelemetry.set(key, {
      hosts: new Set(),
      telemetry: 0,
      alerts: 0,
      suspiciousConnections: 0,
      suspiciousFiles: 0,
      securityEvents: 0,
      dbAlerts: 0,
      processSamples: 0,
      fileEvents: 0,
      networkEvents: 0,
      logEvents: 0,
      roles: new Map()
    });
  }
  return metrics.segmentTelemetry.get(key);
}

function getHostMetrics(hostId, role, segment) {
  const normalizedHost = normalizeLabel(hostId);
  if (!metrics.hostTelemetry.has(normalizedHost)) {
    metrics.hostTelemetry.set(normalizedHost, {
      hostId: normalizedHost,
      role: normalizeLabel(role),
      segment: normalizeLabel(segment),
      telemetry: 0,
      alerts: 0,
      suspiciousConnections: 0,
      suspiciousFiles: 0,
      securityEvents: 0,
      dbAlerts: 0
    });
  }

  const hostMetrics = metrics.hostTelemetry.get(normalizedHost);
  hostMetrics.role = normalizeLabel(role);
  hostMetrics.segment = normalizeLabel(segment);
  return hostMetrics;
}

function incrementMapCount(map, key, amount = 1) {
  map.set(key, (map.get(key) || 0) + amount);
}

function resolveSegment(hostId, telemetry = null) {
  const normalizedHostId = normalizeLabel(hostId);
  if (HOST_SEGMENT_MAP[normalizedHostId]) return HOST_SEGMENT_MAP[normalizedHostId];

  if (telemetry && telemetry.source === 'edr-middleware') {
    return 'backend-clinical-segment';
  }
  if (normalizedHostId.includes('gateway')) return 'edge';
  if (normalizedHostId.includes('db')) return 'data-private';
  if (normalizedHostId.includes('monitor') || normalizedHostId.includes('grafana') || normalizedHostId.includes('prometheus')) {
    return 'observability';
  }
  if (normalizedHostId.includes('controller') || normalizedHostId.includes('iam')) return 'control';
  if (normalizedHostId.includes('backend')) return 'backend-clinical-segment';
  return 'unknown';
}

function parseLegacySummaryMetrics() {
  try {
    if (!fs.existsSync(LOG_FILE)) return;

    const lines = readTailLines(LOG_FILE, MAX_TEXT_LOG_LINES);

    metrics.isolation_tests_total = 0;
    metrics.isolation_tests_passed = 0;
    metrics.isolation_tests_failed = 0;
    metrics.allowed_connections = 0;
    metrics.blocked_attempts = 0;
    metrics.security_violations = 0;

    lines.forEach((line) => {
      try {
        const jsonMatch = line.match(/\{.*\}/);
        const data = jsonMatch ? JSON.parse(jsonMatch[0]) : null;

        if (line.includes('[SDP_TEST]')) {
          metrics.isolation_tests_total += 1;
          if (data && data.passed === true) metrics.isolation_tests_passed += 1;
          if (data && data.passed === false) metrics.isolation_tests_failed += 1;
        }

        if (line.includes('[ACCESS_ALLOWED]')) metrics.allowed_connections += 1;
        if (line.includes('[ACCESS_BLOCKED]')) metrics.blocked_attempts += 1;
        if (line.includes('[SECURITY_VIOLATION]')) metrics.security_violations += 1;
        if (line.includes('[SECURITY_SCORE]') && data && data.score) {
          metrics.security_score = parseFloat(data.score);
        }
      } catch (err) {
        // Ignore malformed legacy log lines.
      }
    });
  } catch (error) {
    console.error('Error parsing legacy log file:', error.message);
  }
}

function parseTelemetryMetrics() {
  const entries = readJsonLines(TELEMETRY_LOG);
  metrics.telemetry_received = entries.length;

  for (const entry of entries) {
    const segment = resolveSegment(entry.hostId, entry);
    const role = normalizeLabel(entry.userRole);
    const segmentMetrics = getSegmentMetrics(segment);
    const hostMetrics = getHostMetrics(entry.hostId, role, segment);

    segmentMetrics.telemetry += 1;
    segmentMetrics.hosts.add(hostMetrics.hostId);
    segmentMetrics.processSamples += Array.isArray(entry.processes) ? entry.processes.length : 0;
    segmentMetrics.fileEvents += Array.isArray(entry.files) ? entry.files.length : 0;
    segmentMetrics.networkEvents += Array.isArray(entry.network) ? entry.network.length : 0;
    segmentMetrics.logEvents += Array.isArray(entry.logs) ? entry.logs.length : 0;
    incrementMapCount(segmentMetrics.roles, role);

    hostMetrics.telemetry += 1;

    const suspiciousConnections = Array.isArray(entry.network)
      ? entry.network.filter((item) => item && item.suspicious).length
      : 0;
    const suspiciousFiles = Array.isArray(entry.files)
      ? entry.files.filter((item) => item && item.type === 'SUSPICIOUS_FILE').length
      : 0;
    const securityEvents = Array.isArray(entry.logs)
      ? entry.logs.filter((item) => item && item.type === 'SECURITY_EVENT').length
      : 0;
    const dbAlerts = entry.dbActivity && Array.isArray(entry.dbActivity.alerts)
      ? entry.dbActivity.alerts.length
      : 0;
    const alerts = Array.isArray(entry.alerts) ? entry.alerts.length : 0;

    segmentMetrics.suspiciousConnections += suspiciousConnections;
    segmentMetrics.suspiciousFiles += suspiciousFiles;
    segmentMetrics.securityEvents += securityEvents;
    segmentMetrics.dbAlerts += dbAlerts;
    segmentMetrics.alerts += alerts;

    hostMetrics.suspiciousConnections += suspiciousConnections;
    hostMetrics.suspiciousFiles += suspiciousFiles;
    hostMetrics.securityEvents += securityEvents;
    hostMetrics.dbAlerts += dbAlerts;
    hostMetrics.alerts += alerts;

    if (Array.isArray(entry.alerts)) {
      for (const alert of entry.alerts) {
        const eventType = normalizeLabel(alert.type || alert.eventType || alert.event || 'alert');
        incrementMapCount(metrics.eventTypeTotals, `${segment}|${eventType}`);
      }
    }

    if (entry.eventType) {
      incrementMapCount(metrics.eventTypeTotals, `${segment}|${normalizeLabel(entry.eventType)}`);
    }
  }
}

function parseIsolationMetrics() {
  const isolations = readJsonFile(ISOLATIONS_FILE, []);
  if (!Array.isArray(isolations)) return;

  for (const isolation of isolations) {
    const details = isolation.alert && isolation.alert.details ? isolation.alert.details : {};
    const segment = normalizeLabel(
      details.segmentId ||
      details.sdpSegmentId ||
      (Array.isArray(isolation.iamActions)
        ? isolation.iamActions.find((item) => item && item.type === 'isolate_segment' && item.segmentId)
          && isolation.iamActions.find((item) => item && item.type === 'isolate_segment' && item.segmentId).segmentId
        : null) ||
      resolveSegment(isolation.hostId)
    );
    const action = normalizeLabel(isolation.action || isolation.reason || 'unknown_action');

    incrementMapCount(metrics.actionTotals, `${segment}|${action}`);
  }
}

async function parseSpaStateMetrics() {
  let directory = {};
  let health = {};

  try {
    directory = await fetchJson(`${SPA_CONTROLLER_BASE_URL}/directory`);
  } catch (err) {
    directory = {};
  }

  try {
    health = await fetchJson(`${SPA_CONTROLLER_BASE_URL}/health`);
  } catch (err) {
    health = {};
  }

  metrics.gateways = Array.isArray(directory.gateways) ? directory.gateways : [];
  metrics.services = Array.isArray(directory.services) ? directory.services : [];

  const isolatedSegments = Array.isArray(health.isolatedSegments) ? health.isolatedSegments : [];
  for (const isolation of isolatedSegments) {
    const segmentId = normalizeLabel(isolation.segmentId);
    metrics.isolatedSegments.set(segmentId, {
      segmentId,
      serviceId: normalizeLabel(isolation.serviceId),
      reason: normalizeLabel(isolation.reason),
      affectedServices: Array.isArray(isolation.affectedServices) ? isolation.affectedServices : []
    });
  }
}

async function refreshMetrics() {
  const fresh = createEmptyMetrics();
  Object.assign(metrics, fresh);

  parseLegacySummaryMetrics();
  parseTelemetryMetrics();
  parseIsolationMetrics();
  await parseSpaStateMetrics();

  metrics.last_update = Date.now();
}

function generateMetrics() {
  const timestamp = Date.now();
  const lines = [
    '# HELP sdp_policy_tests_total Total number of SDP access control tests',
    '# TYPE sdp_policy_tests_total counter',
    promLine('sdp_policy_tests_total', metrics.isolation_tests_total, null, timestamp),
    '',
    '# HELP sdp_policy_tests_passed Number of passed isolation tests',
    '# TYPE sdp_policy_tests_passed counter',
    promLine('sdp_policy_tests_passed', metrics.isolation_tests_passed, null, timestamp),
    '',
    '# HELP sdp_policy_tests_failed Number of failed isolation tests',
    '# TYPE sdp_policy_tests_failed counter',
    promLine('sdp_policy_tests_failed', metrics.isolation_tests_failed, null, timestamp),
    '',
    '# HELP network_allowed_connections Total number of allowed network connections',
    '# TYPE network_allowed_connections counter',
    promLine('network_allowed_connections', metrics.allowed_connections, null, timestamp),
    '',
    '# HELP network_blocked_attempts Total number of blocked connection attempts',
    '# TYPE network_blocked_attempts counter',
    promLine('network_blocked_attempts', metrics.blocked_attempts, null, timestamp),
    '',
    '# HELP network_security_violations Total number of security violations detected',
    '# TYPE network_security_violations counter',
    promLine('network_security_violations', metrics.security_violations, null, timestamp),
    '',
    '# HELP network_security_score Overall network security score (0-100)',
    '# TYPE network_security_score gauge',
    promLine('network_security_score', metrics.security_score, null, timestamp),
    '',
    '# HELP network_telemetry_received_total Total telemetry messages received',
    '# TYPE network_telemetry_received_total counter',
    promLine('network_telemetry_received_total', metrics.telemetry_received, null, timestamp),
    '',
    '# HELP sdp_policy_pass_rate Percentage of isolation tests passed',
    '# TYPE sdp_policy_pass_rate gauge',
    promLine(
      'sdp_policy_pass_rate',
      metrics.isolation_tests_total > 0
        ? ((metrics.isolation_tests_passed / metrics.isolation_tests_total) * 100).toFixed(2)
        : 0,
      null,
      timestamp
    ),
    '',
    '# HELP network_monitoring_last_update Timestamp of last metrics update',
    '# TYPE network_monitoring_last_update gauge',
    promLine('network_monitoring_last_update', metrics.last_update, null, timestamp),
    '',
    '# HELP sdp_segment_hosts Number of unique hosts observed in each segment',
    '# TYPE sdp_segment_hosts gauge'
  ];

  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_hosts', entry.hosts.size, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_telemetry_total Total telemetry entries observed in each segment', '# TYPE sdp_segment_telemetry_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_telemetry_total', entry.telemetry, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_alerts_total Total alerts observed in each segment', '# TYPE sdp_segment_alerts_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_alerts_total', entry.alerts, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_suspicious_connections_total Total suspicious connections observed in each segment', '# TYPE sdp_segment_suspicious_connections_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_suspicious_connections_total', entry.suspiciousConnections, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_suspicious_files_total Total suspicious files observed in each segment', '# TYPE sdp_segment_suspicious_files_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_suspicious_files_total', entry.suspiciousFiles, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_security_events_total Total security log events observed in each segment', '# TYPE sdp_segment_security_events_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_security_events_total', entry.securityEvents, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_db_alerts_total Total database alerts observed in each segment', '# TYPE sdp_segment_db_alerts_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_db_alerts_total', entry.dbAlerts, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_process_samples_total Total process samples observed in each segment', '# TYPE sdp_segment_process_samples_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_process_samples_total', entry.processSamples, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_file_events_total Total file events observed in each segment', '# TYPE sdp_segment_file_events_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_file_events_total', entry.fileEvents, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_network_events_total Total network events observed in each segment', '# TYPE sdp_segment_network_events_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    lines.push(promLine('sdp_segment_network_events_total', entry.networkEvents, { segment }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_role_activity_total Telemetry activity grouped by segment and role', '# TYPE sdp_segment_role_activity_total gauge');
  for (const [segment, entry] of metrics.segmentTelemetry.entries()) {
    for (const [role, total] of entry.roles.entries()) {
      lines.push(promLine('sdp_segment_role_activity_total', total, { segment, role }, timestamp));
    }
  }

  lines.push('', '# HELP sdp_host_telemetry_total Telemetry entries grouped by host', '# TYPE sdp_host_telemetry_total gauge');
  for (const entry of metrics.hostTelemetry.values()) {
    lines.push(promLine('sdp_host_telemetry_total', entry.telemetry, {
      host_id: entry.hostId,
      segment: entry.segment,
      role: entry.role
    }, timestamp));
  }

  lines.push('', '# HELP sdp_host_alerts_total Alerts grouped by host', '# TYPE sdp_host_alerts_total gauge');
  for (const entry of metrics.hostTelemetry.values()) {
    lines.push(promLine('sdp_host_alerts_total', entry.alerts, {
      host_id: entry.hostId,
      segment: entry.segment,
      role: entry.role
    }, timestamp));
  }

  lines.push('', '# HELP sdp_event_type_total Event totals grouped by segment and event type', '# TYPE sdp_event_type_total gauge');
  for (const [key, total] of metrics.eventTypeTotals.entries()) {
    const [segment, eventType] = key.split('|');
    lines.push(promLine('sdp_event_type_total', total, { segment, event_type: eventType }, timestamp));
  }

  lines.push('', '# HELP sdp_isolation_actions_total Isolation and restriction actions grouped by segment', '# TYPE sdp_isolation_actions_total gauge');
  for (const [key, total] of metrics.actionTotals.entries()) {
    const [segment, action] = key.split('|');
    lines.push(promLine('sdp_isolation_actions_total', total, { segment, action }, timestamp));
  }

  lines.push('', '# HELP sdp_segment_isolated Current isolation state for a segment', '# TYPE sdp_segment_isolated gauge');
  for (const isolation of metrics.isolatedSegments.values()) {
    lines.push(promLine('sdp_segment_isolated', 1, {
      segment: isolation.segmentId,
      service_id: isolation.serviceId,
      reason: isolation.reason
    }, timestamp));
  }

  lines.push('', '# HELP sdp_gateway_registered Registered gateways discovered from SPA state', '# TYPE sdp_gateway_registered gauge');
  for (const gateway of metrics.gateways) {
    lines.push(promLine('sdp_gateway_registered', 1, {
      gateway_id: normalizeLabel(gateway.gatewayId),
      gateway_type: normalizeLabel(gateway.gatewayType),
      url: normalizeLabel(gateway.url)
    }, timestamp));
  }

  lines.push('', '# HELP sdp_service_registered Registered services discovered from SPA state', '# TYPE sdp_service_registered gauge');
  for (const service of metrics.services) {
    lines.push(promLine('sdp_service_registered', 1, {
      service_id: normalizeLabel(service.serviceId),
      segment: normalizeLabel(service.segmentId),
      entry_gateway_id: normalizeLabel(service.entryGatewayId),
      internal_gateway_id: normalizeLabel(service.internalGatewayId)
    }, timestamp));
  }

  return `${lines.join('\n')}\n`;
}

const server = http.createServer(async (req, res) => {
  if (req.url === '/metrics') {
    try {
      await refreshMetrics();
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(generateMetrics());
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(`metrics_refresh_error ${escapeLabelValue(err.message)}\n`);
    }
    return;
  }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'healthy', uptime: process.uptime() }));
    return;
  }

  if (req.url === '/telemetry' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ recentTelemetry }));
    return;
  }

  if (req.url === '/ingest/telemetry' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        data.receivedAt = new Date().toISOString();
        fs.appendFile(TELEMETRY_LOG, `${JSON.stringify(data)}\n`, (err) => {
          if (err) console.error('Failed to write telemetry:', err.message);
        });
        recentTelemetry.push(data);
        if (recentTelemetry.length > RECENT_TELEMETRY_MAX) recentTelemetry.shift();
        metrics.telemetry_received += 1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid json' }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('Not Found');
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.stack || err.message || err);
  try {
    fs.appendFileSync(path.join(LOG_DIR, 'error.log'), `${new Date().toISOString()} UNCaught: ${err.stack || err}\n`);
  } catch (appendErr) {
    // Ignore logging failures in fatal path.
  }
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
  try {
    fs.appendFileSync(path.join(LOG_DIR, 'error.log'), `${new Date().toISOString()} UnhandledRejection: ${reason}\n`);
  } catch (appendErr) {
    // Ignore secondary logging failures.
  }
});

server.on('error', (err) => {
  console.error('Server error:', err.message || err);
  if (err && err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} already in use. Stop other services or set METRICS_PORT to a different port.`);
  }
  try {
    fs.appendFileSync(path.join(LOG_DIR, 'error.log'), `${new Date().toISOString()} ServerError: ${err.stack || err}\n`);
  } catch (appendErr) {
    // Ignore secondary logging failures.
  }
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n${'='.repeat(80)}`);
  console.log('PROMETHEUS METRICS EXPORTER');
  console.log(`${'='.repeat(80)}\n`);
  console.log(`Listening on port ${PORT}`);
  console.log(`Metrics endpoint: http://0.0.0.0:${PORT}/metrics`);
  console.log(`Health endpoint: http://0.0.0.0:${PORT}/health`);
  console.log('\nSegment-aware telemetry metrics enabled.\n');
});

setInterval(() => {
  refreshMetrics().catch((err) => {
    console.error('Periodic metrics refresh failed:', err.message);
  });
}, 30000);
refreshMetrics().catch((err) => {
  console.error('Initial metrics refresh failed:', err.message);
});
