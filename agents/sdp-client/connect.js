const http = require('http');
const https = require('https');

function getArg(name, fallback = '') {
  const prefix = `--${name}=`;
  const match = process.argv.find((item) => item.startsWith(prefix));
  return match ? match.slice(prefix.length) : fallback;
}

const controllerUrl = getArg('controller-url', process.env.SDP_ACCESS_CONTROLLER_URL || 'http://127.0.0.1:7001');
const clientId = getArg('client-id', process.env.SDP_CLIENT_ID || '');
const clientSecret = getArg('client-secret', process.env.SDP_CLIENT_SECRET || '');
const serviceId = getArg('service-id', process.env.SDP_SERVICE_ID || 'hospital-backend-app');
const requestedPath = getArg('requested-path', process.env.SDP_REQUESTED_PATH || '/api/patients');
const userToken = getArg('user-token', process.env.SDP_USER_TOKEN || '');
const method = getArg('method', process.env.SDP_METHOD || 'GET');

if (!clientId || !clientSecret) {
  console.error('client-id and client-secret are required');
  process.exit(1);
}

const payload = JSON.stringify({
  clientId,
  clientSecret,
  serviceId,
  requestedPath,
  method,
  userToken
});

const url = new URL(`${controllerUrl}/connect`);
const client = url.protocol === 'https:' ? https : http;

const req = client.request({
  hostname: url.hostname,
  port: url.port || (url.protocol === 'https:' ? 443 : 80),
  path: url.pathname,
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload)
  }
}, (res) => {
  let raw = '';
  res.on('data', (chunk) => { raw += chunk; });
  res.on('end', () => {
    try {
      const parsed = JSON.parse(raw || '{}');
      console.log(JSON.stringify(parsed));
      process.exit(res.statusCode && res.statusCode >= 400 ? 1 : 0);
    } catch (err) {
      console.error(raw);
      process.exit(1);
    }
  });
});

req.on('error', (err) => {
  console.error(err.message);
  process.exit(1);
});

req.write(payload);
req.end();
