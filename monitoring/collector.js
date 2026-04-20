const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.COLLECTOR_PORT ? parseInt(process.env.COLLECTOR_PORT, 10) : 9090;
const DEFAULT_LOG_DIR = process.platform === 'win32' ? 'C:\\logs' : '/logs';
const LOG_DIR = process.env.LOG_DIR || DEFAULT_LOG_DIR;
const TELEMETRY_LOG = path.join(LOG_DIR, 'telemetry.log');
const MAX_JSON_LOG_LINES = process.env.MAX_JSON_LOG_LINES ? parseInt(process.env.MAX_JSON_LOG_LINES, 10) : 2000;
const RECENT_TELEMETRY_MAX = process.env.RECENT_TELEMETRY_MAX ? parseInt(process.env.RECENT_TELEMETRY_MAX, 10) : 100;
const MAX_TAIL_BYTES = process.env.MAX_TAIL_BYTES ? parseInt(process.env.MAX_TAIL_BYTES, 10) : (1024 * 1024);

let nextSequence = 1;
const recentTelemetry = [];

try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
} catch (err) {
  console.error(`Failed to create log directory ${LOG_DIR}:`, err.message);
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

    if (start > 0) {
      const firstNewline = text.indexOf('\n');
      text = firstNewline >= 0 ? text.slice(firstNewline + 1) : '';
    }

    return text;
  } finally {
    fs.closeSync(fd);
  }
}

function loadRecentTelemetry() {
  if (!fs.existsSync(TELEMETRY_LOG)) return;

  const lines = readTailText(TELEMETRY_LOG)
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-MAX_JSON_LOG_LINES);

  for (const line of lines) {
    try {
      const item = JSON.parse(line);
      recentTelemetry.push(item);
      if (typeof item.sequence === 'number' && item.sequence >= nextSequence) {
        nextSequence = item.sequence + 1;
      }
    } catch (err) {
      // Ignore malformed historical lines during bootstrap.
    }
  }

  while (recentTelemetry.length > RECENT_TELEMETRY_MAX) {
    recentTelemetry.shift();
  }
}

function appendTelemetry(data) {
  const entry = {
    ...data,
    sequence: nextSequence++,
    receivedAt: new Date().toISOString()
  };

  recentTelemetry.push(entry);
  if (recentTelemetry.length > RECENT_TELEMETRY_MAX) {
    recentTelemetry.shift();
  }

  fs.appendFile(TELEMETRY_LOG, `${JSON.stringify(entry)}\n`, (err) => {
    if (err) console.error('Failed to write telemetry:', err.message);
  });

  return entry;
}

loadRecentTelemetry();

const server = http.createServer((req, res) => {
  const requestUrl = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);

  if (requestUrl.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'healthy',
      service: 'telemetry-collector',
      logDir: LOG_DIR,
      cachedItems: recentTelemetry.length,
      latestSequence: nextSequence - 1,
      uptime: process.uptime()
    }));
    return;
  }

  if (requestUrl.pathname === '/telemetry' && req.method === 'GET') {
    const sinceSequence = requestUrl.searchParams.has('since')
      ? parseInt(requestUrl.searchParams.get('since'), 10)
      : null;
    const items = Number.isFinite(sinceSequence)
      ? recentTelemetry.filter((item) => typeof item.sequence === 'number' && item.sequence > sinceSequence)
      : recentTelemetry;

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      recentTelemetry: items,
      latestSequence: nextSequence - 1,
      totalCached: recentTelemetry.length
    }));
    return;
  }

  if (requestUrl.pathname === '/ingest/telemetry' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const entry = appendTelemetry(data);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, sequence: entry.sequence, receivedAt: entry.receivedAt }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid json' }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.on('error', (err) => {
  console.error('Collector server error:', err.message || err);
  process.exit(1);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Telemetry collector listening on http://0.0.0.0:${PORT}`);
  console.log(`Telemetry endpoint: http://0.0.0.0:${PORT}/ingest/telemetry`);
  console.log(`Telemetry view: http://0.0.0.0:${PORT}/telemetry`);
});
