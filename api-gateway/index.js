const cors = require('cors');
const express = require('express');
const fs = require('fs');
const helmet = require('helmet');
const http = require('http');
const https = require('https');
const jwt = require('jsonwebtoken');

const PORT = parseInt(process.env.PORT || '8443', 10);
const JWT_SECRET = readSecret('JWT_SECRET', 'sdp_phase2_shared_secret_change_me');
const IAM_URL = process.env.IAM_URL || 'http://iam:4000';
const BACKEND_URL = process.env.BACKEND_URL || 'https://backend-internal-gateway:3443';
const SDP_CONTROLLER_URL = process.env.SDP_CONTROLLER_URL || 'http://sdp-controller:7000';
const SDP_ACCESS_CONTROLLER_URL = process.env.SDP_ACCESS_CONTROLLER_URL || 'http://spa-controller:7001';
const SDP_REGISTRATION_TOKEN = readSecret('SDP_REGISTRATION_TOKEN', 'sdp_register_demo_token');
const GATEWAY_ID = process.env.GATEWAY_ID || 'external-api-gateway';
const GATEWAY_PUBLIC_URL = process.env.GATEWAY_PUBLIC_URL || 'https://api-gateway:8443';
const SDP_ENFORCEMENT = process.env.SDP_ENFORCEMENT !== 'false';
const SDP_FAIL_OPEN = process.env.SDP_FAIL_OPEN === 'true';
const TLS_SERVER_CERT = process.env.TLS_SERVER_CERT || '/certs/external-gateway/external-gateway-server.crt';
const TLS_SERVER_KEY = process.env.TLS_SERVER_KEY || '/certs/external-gateway/external-gateway-server.key';
const TLS_CA_CERT = process.env.TLS_CA_CERT || '/certs/ca/ca.crt';
const INTERNAL_TLS_CLIENT_CERT = process.env.INTERNAL_TLS_CLIENT_CERT || '/certs/external-gateway/external-gateway-client.crt';
const INTERNAL_TLS_CLIENT_KEY = process.env.INTERNAL_TLS_CLIENT_KEY || '/certs/external-gateway/external-gateway-client.key';

function readSecret(envName, demoFallback) {
  const value = process.env[envName];
  if (typeof value === 'string' && value.length > 0) return value;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`${envName} is required in production`);
  }
  return demoFallback;
}

const PUBLIC_PATHS = [
  '/api/login',
  '/api/mfa',
  '/api/token',
  '/api/logout',
  '/api/me',
  '/api/admin/mfa/secret',
  '/api/security/revoke-user',
  '/api/security/block-ip',
  '/api/health',
  '/api/monitoring/health'
];

const BACKEND_PREFIXES = [
  '/api/patients',
  '/api/appointments',
  '/api/vitals',
  '/api/prescriptions',
  '/api/lab',
  '/api/billing',
  '/api/pharmacy',
  '/api/files',
  '/api/audit',
  '/api/monitoring',
  '/api/dashboard',
  '/api/doctor',
  '/api/receptionist',
  '/api/nurse',
  '/api/accountant',
  '/api/notifications',
  '/api/encryption',
  '/api/doctors',
  '/api/users'
];

function startsWithAny(pathname, prefixes) {
  return prefixes.some((prefix) => pathname === prefix || pathname.startsWith(prefix + '/'));
}

function isPublicPath(pathname) {
  return startsWithAny(pathname, PUBLIC_PATHS);
}

function isBackendPath(pathname) {
  return startsWithAny(pathname, BACKEND_PREFIXES);
}

function targetFor(pathname) {
  if (isBackendPath(pathname)) {
    return BACKEND_URL;
  }
  return IAM_URL;
}

function parseToken(req) {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

function parseGrantToken(req) {
  const header = req.headers['x-sdp-grant'];
  return typeof header === 'string' && header.trim().length > 0 ? header.trim() : null;
}

function parseClientId(req) {
  const header = req.headers['x-sdp-client-id'];
  return typeof header === 'string' && header.trim().length > 0 ? header.trim() : null;
}

function getPeerCertificateCn(req) {
  const cert = req.socket && typeof req.socket.getPeerCertificate === 'function'
    ? req.socket.getPeerCertificate()
    : null;
  if (!cert || !cert.subject) {
    return null;
  }
  return cert.subject.CN || null;
}

function postJson(urlString, payload, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;
    const body = JSON.stringify(payload);

    const req = client.request({
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
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
          reject(new Error('Invalid controller response JSON'));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Controller request timed out'));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function authorizeWithController({ pathname, method, identity, sourceIp }) {
  const result = await postJson(`${SDP_CONTROLLER_URL}/authorize`, {
    pathname,
    method,
    identity,
    sourceIp,
    enforcement: SDP_ENFORCEMENT
  });

  if (result.status >= 400) {
    throw new Error(`Controller error status ${result.status}`);
  }
  return result.body;
}

async function authorizeServiceGrant({ pathname, method, grantToken, clientCertCn }) {
  const result = await postJson(`${SDP_ACCESS_CONTROLLER_URL}/authorize/gateway`, {
    gatewayId: GATEWAY_ID,
    grantToken,
    pathname,
    method,
    clientCertCn
  });

  if (result.status >= 400) {
    throw new Error(`Access controller error status ${result.status}`);
  }
  return result.body;
}

async function authorizeSpaClient({ clientId, clientCertCn, sourceIp }) {
  const result = await postJson(`${SDP_ACCESS_CONTROLLER_URL}/authorize/client`, {
    clientId,
    clientCertCn,
    sourceIp
  });

  if (result.status >= 400) {
    throw new Error(`Access controller client auth error status ${result.status}`);
  }
  return result.body;
}

async function registerGatewayWithAccessController() {
  try {
    await postJson(`${SDP_ACCESS_CONTROLLER_URL}/register/gateway`, {
      gatewayId: GATEWAY_ID,
      gatewayType: 'external',
      url: GATEWAY_PUBLIC_URL,
      serviceIds: ['hospital-backend-app'],
      description: 'External gateway for hospital services'
    }, {
      'x-registration-token': SDP_REGISTRATION_TOKEN
    });
    console.log(`[SDP] Registered gateway ${GATEWAY_ID} with access controller`);
    return true;
  } catch (err) {
    console.warn(`[SDP] Gateway registration failed: ${err.message}`);
    return false;
  }
}

function createProxyRequest(req, res, targetBase) {
  const url = new URL(targetBase);
  const isHttps = url.protocol === 'https:';
  const requestClient = isHttps ? https : http;

  const options = {
    hostname: url.hostname,
    port: url.port || (isHttps ? 443 : 80),
    method: req.method,
    path: req.originalUrl,
    headers: {
      ...req.headers,
      host: url.host,
      'x-sdp-enforced': 'true'
    }
  };

  if (isHttps) {
    options.ca = fs.readFileSync(TLS_CA_CERT);
    options.cert = fs.readFileSync(INTERNAL_TLS_CLIENT_CERT);
    options.key = fs.readFileSync(INTERNAL_TLS_CLIENT_KEY);
    options.rejectUnauthorized = true;
    options.servername = url.hostname;
  }

  const proxyReq = requestClient.request(options, (proxyRes) => {
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
      res.status(502).json({ success: false, error: 'SDP gateway upstream error', details: err.message });
    }
  });

  req.pipe(proxyReq);
}

const app = express();
app.use(helmet());
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-sdp-grant', 'x-sdp-client-id']
}));

app.get('/health', (req, res) => {
  res.json({
    ok: true,
    service: 'sdp-gateway',
    gatewayId: GATEWAY_ID,
    enforcement: SDP_ENFORCEMENT,
    failOpen: SDP_FAIL_OPEN,
    controllerUrl: SDP_CONTROLLER_URL,
    accessControllerUrl: SDP_ACCESS_CONTROLLER_URL,
    tls: true,
    ts: new Date().toISOString()
  });
});

app.use('/api', async (req, res, next) => {
  const pathname = req.originalUrl.split('?')[0];
  const isBackendRoute = isBackendPath(pathname);
  const clientCertCn = getPeerCertificateCn(req);
  const clientId = parseClientId(req);

  if (!req.client || !req.client.authorized) {
    return res.status(401).json({ success: false, error: 'SDP denied: mTLS client certificate required' });
  }

  if (pathname !== '/api/health' && pathname !== '/api/monitoring/health') {
    if (!clientId) {
      return res.status(403).json({ success: false, error: 'SDP denied: missing SPA client identifier' });
    }

    try {
      const spaDecision = await authorizeSpaClient({
        clientId,
        clientCertCn,
        sourceIp: req.ip || req.connection.remoteAddress || ''
      });
      if (!spaDecision.allow) {
        return res.status(403).json({ success: false, error: `SDP denied: ${spaDecision.reason || 'spa_denied'}` });
      }
    } catch (err) {
      return res.status(503).json({
        success: false,
        error: 'SDP denied: SPA controller unavailable',
        details: err.message
      });
    }
  }

  if (isBackendRoute) {
    const grantToken = parseGrantToken(req);
    if (!grantToken) {
      return res.status(403).json({ success: false, error: 'SDP denied: missing service grant' });
    }

    try {
      const grantDecision = await authorizeServiceGrant({
        pathname,
        method: req.method,
        grantToken,
        clientCertCn
      });

      if (!grantDecision.allow) {
        return res.status(403).json({ success: false, error: `SDP denied: ${grantDecision.reason || 'invalid_service_grant'}` });
      }

      req.serviceGrant = grantDecision;
    } catch (err) {
      return res.status(503).json({
        success: false,
        error: 'SDP denied: access controller unavailable',
        details: err.message
      });
    }
  }

  if (!SDP_ENFORCEMENT || isPublicPath(pathname)) {
    return next();
  }

  const token = parseToken(req);
  if (!token) {
    return res.status(401).json({ success: false, error: 'SDP denied: missing token' });
  }

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ success: false, error: 'SDP denied: invalid or expired token' });
  }

  try {
    const decision = await authorizeWithController({
      pathname,
      method: req.method,
      identity: payload,
      sourceIp: req.ip || req.connection.remoteAddress || 'unknown'
    });

    if (!decision.allow) {
      return res.status(403).json({ success: false, error: `SDP denied: ${decision.reason || 'policy_denied'}` });
    }

    req.sdpDecision = decision;
    req.sdpIdentity = payload;
    return next();
  } catch (err) {
    if (SDP_FAIL_OPEN) {
      req.sdpDecision = { allow: true, reason: 'controller_unreachable_fail_open' };
      req.sdpIdentity = payload;
      return next();
    }

    return res.status(503).json({
      success: false,
      error: 'SDP denied: controller unavailable',
      details: err.message
    });
  }
});

app.use('/api', (req, res) => {
  const pathname = req.originalUrl.split('?')[0];
  const target = req.serviceGrant && req.serviceGrant.upstreamUrl
    ? req.serviceGrant.upstreamUrl
    : targetFor(pathname);
  createProxyRequest(req, res, target);
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Not found' });
});

const tlsOptions = {
  cert: fs.readFileSync(TLS_SERVER_CERT),
  key: fs.readFileSync(TLS_SERVER_KEY),
  ca: fs.readFileSync(TLS_CA_CERT),
  requestCert: true,
  rejectUnauthorized: true
};

https.createServer(tlsOptions, app).listen(PORT, '0.0.0.0', () => {
  console.log(`[SDP] API Gateway listening on https://0.0.0.0:${PORT}`);
  console.log(`[SDP] IAM upstream: ${IAM_URL}`);
  console.log(`[SDP] Backend upstream: ${BACKEND_URL}`);
  console.log(`[SDP] Controller: ${SDP_CONTROLLER_URL}`);
  console.log(`[SDP] Access Controller: ${SDP_ACCESS_CONTROLLER_URL}`);
  console.log(`[SDP] Enforcement: ${SDP_ENFORCEMENT ? 'enabled' : 'disabled'} | FailOpen: ${SDP_FAIL_OPEN}`);
  registerGatewayWithAccessController().then((registered) => {
    if (!registered) {
      const retry = setInterval(async () => {
        const ok = await registerGatewayWithAccessController();
        if (ok) {
          clearInterval(retry);
        }
      }, 5000);
    }
  });
});
