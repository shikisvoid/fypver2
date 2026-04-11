const express = require('express');
const fs = require('fs');
const helmet = require('helmet');
const http = require('http');
const https = require('https');

const PORT = parseInt(process.env.PORT || '3443', 10);
const ORIGIN_URL = process.env.ORIGIN_URL || 'http://backend:3000';
const CONTROLLER_URL = process.env.SDP_ACCESS_CONTROLLER_URL || 'http://spa-controller:7001';
const REGISTRATION_TOKEN = readSecret('SDP_REGISTRATION_TOKEN', 'sdp_register_demo_token');
const GATEWAY_ID = process.env.GATEWAY_ID || 'backend-internal-gateway';
const GATEWAY_URL = process.env.GATEWAY_URL || 'https://backend-internal-gateway:3443';
const SERVICE_ID = process.env.SERVICE_ID || 'hospital-backend-app';
const SERVICE_NAME = process.env.SERVICE_NAME || 'Hospital Backend App';
const TLS_SERVER_CERT = process.env.TLS_SERVER_CERT || '/certs/internal-gateway/internal-gateway-server.crt';
const TLS_SERVER_KEY = process.env.TLS_SERVER_KEY || '/certs/internal-gateway/internal-gateway-server.key';
const TLS_CA_CERT = process.env.TLS_CA_CERT || '/certs/ca/ca.crt';
const PATH_PREFIXES = (process.env.SERVICE_PATH_PREFIXES || '/api/patients,/api/appointments,/api/vitals,/api/prescriptions,/api/lab,/api/billing,/api/pharmacy,/api/files,/api/audit,/api/monitoring,/api/dashboard,/api/doctor,/api/receptionist,/api/nurse,/api/accountant,/api/notifications,/api/encryption,/api/doctors,/api/users')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

function readSecret(envName, demoFallback) {
  const value = process.env[envName];
  if (typeof value === 'string' && value.length > 0) return value;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`${envName} is required in production`);
  }
  return demoFallback;
}

function postJson(urlString, payload, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const body = JSON.stringify(payload);
    const client = url.protocol === 'https:' ? https : http;

    const req = client.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...extraHeaders
      },
      timeout: 3000
    }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode || 500, body: JSON.parse(raw || '{}') });
        } catch (err) {
          reject(new Error('Invalid JSON response'));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function registerWithController() {
  const headers = { 'x-registration-token': REGISTRATION_TOKEN };
  await postJson(`${CONTROLLER_URL}/register/gateway`, {
    gatewayId: GATEWAY_ID,
    gatewayType: 'internal',
    url: GATEWAY_URL,
    serviceIds: [SERVICE_ID],
    description: 'Internal gateway for backend services'
  }, headers);

  await postJson(`${CONTROLLER_URL}/register/service`, {
    serviceId: SERVICE_ID,
    name: SERVICE_NAME,
    entryGatewayId: 'external-api-gateway',
    internalGatewayId: GATEWAY_ID,
    originUrl: ORIGIN_URL,
    pathPrefixes: PATH_PREFIXES,
    requiresIdentity: true
  }, headers);
}

async function authorizeGrant(req) {
  const grantToken = typeof req.headers['x-sdp-grant'] === 'string' ? req.headers['x-sdp-grant'].trim() : '';
  if (!grantToken) {
    return { allow: false, reason: 'missing_service_grant' };
  }

  const result = await postJson(`${CONTROLLER_URL}/authorize/gateway`, {
    gatewayId: GATEWAY_ID,
    grantToken,
    pathname: req.originalUrl.split('?')[0],
    method: req.method
  });

  if (result.status >= 400) {
    throw new Error(`Access controller error status ${result.status}`);
  }
  return result.body;
}

function proxyRequest(req, res, targetBase) {
  const url = new URL(targetBase);
  const client = url.protocol === 'https:' ? https : http;

  const proxyReq = client.request({
    hostname: url.hostname,
    port: url.port || (url.protocol === 'https:' ? 443 : 80),
    path: req.originalUrl,
    method: req.method,
    headers: {
      ...req.headers,
      host: url.host,
      'x-internal-gateway-id': GATEWAY_ID
    }
  }, (proxyRes) => {
    res.status(proxyRes.statusCode || 502);
    Object.entries(proxyRes.headers || {}).forEach(([key, value]) => {
      if (value !== undefined) {
        res.setHeader(key, value);
      }
    });
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      res.status(502).json({ success: false, error: 'Internal gateway upstream error', details: err.message });
    }
  });

  req.pipe(proxyReq);
}

const app = express();
app.use(helmet());

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'backend-internal-gateway',
    gatewayId: GATEWAY_ID,
    originUrl: ORIGIN_URL,
    tls: true,
    ts: new Date().toISOString()
  });
});

app.use('/api', async (req, res) => {
  if (!req.client || !req.client.authorized) {
    return res.status(401).json({ success: false, error: 'SDP denied: internal gateway requires mTLS' });
  }

  try {
    const decision = await authorizeGrant(req);
    if (!decision.allow) {
      return res.status(403).json({ success: false, error: `SDP denied: ${decision.reason || 'invalid_service_grant'}` });
    }
    return proxyRequest(req, res, ORIGIN_URL);
  } catch (err) {
    return res.status(503).json({ success: false, error: 'Internal gateway authorization failed', details: err.message });
  }
});

const tlsOptions = {
  cert: fs.readFileSync(TLS_SERVER_CERT),
  key: fs.readFileSync(TLS_SERVER_KEY),
  ca: fs.readFileSync(TLS_CA_CERT),
  requestCert: true,
  rejectUnauthorized: true
};

https.createServer(tlsOptions, app).listen(PORT, '0.0.0.0', () => {
  console.log(`[INTERNAL-GW] Backend internal gateway listening on https://0.0.0.0:${PORT}`);
  registerWithController()
    .then(() => console.log(`[INTERNAL-GW] Registered ${GATEWAY_ID} and ${SERVICE_ID} with controller`))
    .catch((err) => {
      console.warn(`[INTERNAL-GW] Registration failed: ${err.message}`);
      const retry = setInterval(async () => {
        try {
          await registerWithController();
          console.log(`[INTERNAL-GW] Registered ${GATEWAY_ID} and ${SERVICE_ID} with controller`);
          clearInterval(retry);
        } catch (retryErr) {
          console.warn(`[INTERNAL-GW] Registration retry failed: ${retryErr.message}`);
        }
      }, 5000);
    });
});
