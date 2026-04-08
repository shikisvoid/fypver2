const crypto = require('crypto');
const dgram = require('dgram');
const express = require('express');
const fs = require('fs');
const helmet = require('helmet');
const http = require('http');
const https = require('https');
const jwt = require('jsonwebtoken');
const path = require('path');

const PORT = parseInt(process.env.PORT || '7001', 10);
const SPA_UDP_PORT = parseInt(process.env.SDP_SPA_UDP_PORT || '62201', 10);
const CONFIG_FILE = process.env.SDP_ACCESS_CONFIG_FILE || path.join(__dirname, 'config.json');
const JWT_SECRET = process.env.JWT_SECRET || 'sdp_phase2_shared_secret_change_me';
const GRANT_SIGNING_SECRET = process.env.SDP_GRANT_SIGNING_SECRET || 'sdp_access_grant_secret_change_me';
const POLICY_ENGINE_URL = process.env.SDP_POLICY_ENGINE_URL || 'http://sdp-controller:7000';

const state = {
  config: {
    version: 'builtin-default',
    grantTtlSec: 600,
    spaAdmissionTtlSec: 300,
    registrationToken: 'sdp_register_demo_token',
    clients: []
  },
  configSource: 'builtin',
  configLoadedAt: new Date().toISOString(),
  configMtimeMs: 0,
  gateways: new Map(),
  services: new Map(),
  spaAdmissions: new Map(),
  usedSpaNonces: new Map()
};

function startsWithAny(pathname, prefixes) {
  return prefixes.some((prefix) => pathname === prefix || pathname.startsWith(prefix + '/'));
}

function normalizePathPrefixes(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((entry) => typeof entry === 'string' && entry.length > 0);
}

function normalizeConfig(raw) {
  const data = raw && typeof raw === 'object' ? raw : {};
  const clients = Array.isArray(data.clients) ? data.clients : [];

  return {
    version: typeof data.version === 'string' ? data.version : 'file-default',
    grantTtlSec: Number.isFinite(data.grantTtlSec) ? Math.max(60, parseInt(data.grantTtlSec, 10)) : 600,
    spaAdmissionTtlSec: Number.isFinite(data.spaAdmissionTtlSec) ? Math.max(30, parseInt(data.spaAdmissionTtlSec, 10)) : 300,
    registrationToken: typeof data.registrationToken === 'string' ? data.registrationToken : 'sdp_register_demo_token',
    clients: clients
      .filter((client) => client && typeof client.clientId === 'string' && typeof client.clientSecret === 'string')
      .map((client) => ({
        clientId: client.clientId,
        clientSecret: client.clientSecret,
        spaSecret: typeof client.spaSecret === 'string' ? client.spaSecret : '',
        certificateCn: typeof client.certificateCn === 'string' ? client.certificateCn : client.clientId,
        description: typeof client.description === 'string' ? client.description : ''
      }))
  };
}

function cleanupExpiredState() {
  const now = Date.now();
  for (const [clientId, admission] of state.spaAdmissions.entries()) {
    if (!admission || admission.expiresAtMs <= now) {
      state.spaAdmissions.delete(clientId);
    }
  }
  for (const [nonceKey, expiresAtMs] of state.usedSpaNonces.entries()) {
    if (expiresAtMs <= now) {
      state.usedSpaNonces.delete(nonceKey);
    }
  }
}

function loadConfigFromDisk() {
  const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
  const parsed = JSON.parse(raw);
  const stat = fs.statSync(CONFIG_FILE);

  state.config = normalizeConfig(parsed);
  state.configSource = CONFIG_FILE;
  state.configLoadedAt = new Date().toISOString();
  state.configMtimeMs = stat.mtimeMs;
}

function refreshConfigIfChanged() {
  try {
    const stat = fs.statSync(CONFIG_FILE);
    if (state.configSource === 'builtin' || stat.mtimeMs !== state.configMtimeMs) {
      loadConfigFromDisk();
      console.log(`[SDP-ACCESS] Config loaded from ${CONFIG_FILE} (version=${state.config.version})`);
    }
  } catch (err) {
    if (state.configSource === 'builtin') {
      console.warn(`[SDP-ACCESS] Using built-in defaults because config is unavailable: ${err.message}`);
    } else {
      console.warn(`[SDP-ACCESS] Keeping previous config after reload failure: ${err.message}`);
    }
  }
}

function postJson(urlString, payload) {
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
        'Content-Length': Buffer.byteLength(body)
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

function getClientRecord(clientId) {
  refreshConfigIfChanged();
  return state.config.clients.find((client) => client.clientId === clientId) || null;
}

function validateSpaAdmission(clientId, clientCertCn) {
  cleanupExpiredState();
  const client = getClientRecord(clientId);
  if (!client) {
    return { allow: false, reason: 'unknown_client' };
  }

  const admission = state.spaAdmissions.get(clientId);
  if (!admission) {
    return { allow: false, reason: 'missing_spa_admission' };
  }

  if (clientCertCn && client.certificateCn && client.certificateCn !== clientCertCn) {
    return { allow: false, reason: 'spa_client_certificate_mismatch' };
  }

  return { allow: true, reason: 'spa_admission_valid' };
}

function createExpectedSpaHmac(client, timestamp, nonce) {
  return crypto
    .createHmac('sha256', client.spaSecret)
    .update(`${client.clientId}.${timestamp}.${nonce}`)
    .digest('hex');
}

function registerSpaAdmission(clientId, remoteAddress) {
  const expiresAtMs = Date.now() + (state.config.spaAdmissionTtlSec * 1000);
  const admission = {
    clientId,
    remoteAddress,
    admittedAt: new Date().toISOString(),
    expiresAtMs
  };
  state.spaAdmissions.set(clientId, admission);
  return admission;
}

function validateSpaPacket(packet, remoteAddress) {
  cleanupExpiredState();
  const clientId = typeof packet.clientId === 'string' ? packet.clientId : '';
  const timestamp = parseInt(packet.timestamp, 10);
  const nonce = typeof packet.nonce === 'string' ? packet.nonce : '';
  const hmac = typeof packet.hmac === 'string' ? packet.hmac.toLowerCase() : '';

  if (!clientId || !Number.isFinite(timestamp) || !nonce || !hmac) {
    return { ok: false, reason: 'invalid_spa_packet' };
  }

  const client = getClientRecord(clientId);
  if (!client || !client.spaSecret) {
    return { ok: false, reason: 'unknown_spa_client' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - timestamp) > 60) {
    return { ok: false, reason: 'spa_clock_skew' };
  }

  const nonceKey = `${clientId}:${nonce}`;
  if (state.usedSpaNonces.has(nonceKey)) {
    return { ok: false, reason: 'spa_replay_detected' };
  }

  const expectedHmac = createExpectedSpaHmac(client, timestamp, nonce);
  if (expectedHmac.length !== hmac.length) {
    return { ok: false, reason: 'invalid_spa_hmac' };
  }

  const expectedBuffer = Buffer.from(expectedHmac, 'utf8');
  const providedBuffer = Buffer.from(hmac, 'utf8');
  if (!crypto.timingSafeEqual(expectedBuffer, providedBuffer)) {
    return { ok: false, reason: 'invalid_spa_hmac' };
  }

  state.usedSpaNonces.set(nonceKey, Date.now() + (state.config.spaAdmissionTtlSec * 1000));
  const admission = registerSpaAdmission(clientId, remoteAddress);
  return { ok: true, admission };
}

function requireRegistrationToken(req, res, next) {
  refreshConfigIfChanged();
  const provided = req.headers['x-registration-token'];
  if (provided !== state.config.registrationToken) {
    return res.status(403).json({ ok: false, error: 'invalid_registration_token' });
  }
  return next();
}

function upsertGateway(body) {
  const gateway = {
    gatewayId: body.gatewayId,
    gatewayType: body.gatewayType === 'internal' ? 'internal' : 'external',
    url: body.url,
    serviceIds: Array.isArray(body.serviceIds) ? body.serviceIds.filter((item) => typeof item === 'string') : [],
    description: typeof body.description === 'string' ? body.description : '',
    registeredAt: new Date().toISOString()
  };
  state.gateways.set(gateway.gatewayId, gateway);
  return gateway;
}

function upsertService(body) {
  const service = {
    serviceId: body.serviceId,
    name: typeof body.name === 'string' ? body.name : body.serviceId,
    entryGatewayId: typeof body.entryGatewayId === 'string' ? body.entryGatewayId : null,
    internalGatewayId: typeof body.internalGatewayId === 'string' ? body.internalGatewayId : null,
    originUrl: typeof body.originUrl === 'string' ? body.originUrl : null,
    pathPrefixes: normalizePathPrefixes(body.pathPrefixes),
    requiresIdentity: body.requiresIdentity !== false,
    registeredAt: new Date().toISOString()
  };
  state.services.set(service.serviceId, service);
  return service;
}

async function authorizeUserForService(service, pathname, method, userToken) {
  if (!service.requiresIdentity) {
    return { allow: true, reason: 'service_public' };
  }

  if (!userToken) {
    return { allow: false, reason: 'missing_user_token' };
  }

  let identity;
  try {
    identity = jwt.verify(userToken, JWT_SECRET);
  } catch (err) {
    return { allow: false, reason: 'invalid_user_token' };
  }

  const targetPath = typeof pathname === 'string' && pathname.length > 0
    ? pathname
    : (service.pathPrefixes[0] || '/');

  if (service.pathPrefixes.length > 0 && !startsWithAny(targetPath, service.pathPrefixes)) {
    return { allow: false, reason: 'path_outside_service_scope' };
  }

  const result = await postJson(`${POLICY_ENGINE_URL}/authorize`, {
    pathname: targetPath,
    method: method || 'GET',
    identity,
    enforcement: true
  });

  if (result.status >= 400) {
    throw new Error(`Policy engine error status ${result.status}`);
  }

  if (!result.body.allow) {
    return { allow: false, reason: result.body.reason || 'policy_denied', identity };
  }

  return { allow: true, reason: result.body.reason || 'policy_allow', identity };
}

function createGrant(service, identity, clientId) {
  const client = getClientRecord(clientId);
  const nowSec = Math.floor(Date.now() / 1000);
  const expiresAtSec = nowSec + state.config.grantTtlSec;
  const payload = {
    iss: 'hospital-sdp-access-controller',
    sub: clientId,
    serviceId: service.serviceId,
    entryGatewayId: service.entryGatewayId,
    internalGatewayId: service.internalGatewayId,
    pathPrefixes: service.pathPrefixes,
    clientCertCn: client ? client.certificateCn : clientId,
    user: identity ? { email: identity.email, role: identity.role } : null,
    iat: nowSec,
    exp: expiresAtSec
  };

  return {
    token: jwt.sign(payload, GRANT_SIGNING_SECRET),
    expiresAt: new Date(expiresAtSec * 1000).toISOString()
  };
}

function authorizeGatewayGrant(grantToken, gatewayId, pathname, clientCertCn) {
  let payload;
  try {
    payload = jwt.verify(grantToken, GRANT_SIGNING_SECRET);
  } catch (err) {
    return { allow: false, reason: 'invalid_grant_token' };
  }

  const service = state.services.get(payload.serviceId);
  if (!service) {
    return { allow: false, reason: 'unknown_service' };
  }

  const entryGatewayId = payload.entryGatewayId;
  const internalGatewayId = payload.internalGatewayId;
  const isGatewayAllowed = gatewayId === entryGatewayId || gatewayId === internalGatewayId;
  if (!isGatewayAllowed) {
    return { allow: false, reason: 'gateway_not_authorized_for_grant' };
  }

  if (Array.isArray(payload.pathPrefixes) && payload.pathPrefixes.length > 0 && pathname && !startsWithAny(pathname, payload.pathPrefixes)) {
    return { allow: false, reason: 'path_not_authorized_for_service' };
  }

  if (clientCertCn && payload.clientCertCn && clientCertCn !== payload.clientCertCn) {
    return { allow: false, reason: 'client_certificate_mismatch' };
  }

  let upstreamUrl = service.originUrl;
  let nextGatewayId = null;
  if (gatewayId === entryGatewayId && internalGatewayId) {
    const internalGateway = state.gateways.get(internalGatewayId);
    if (!internalGateway) {
      return { allow: false, reason: 'internal_gateway_unavailable' };
    }
    upstreamUrl = internalGateway.url;
    nextGatewayId = internalGateway.gatewayId;
  }

  return {
    allow: true,
    reason: 'grant_valid',
    serviceId: service.serviceId,
    upstreamUrl,
    nextGatewayId,
    user: payload.user || null
  };
}

const app = express();
app.use(helmet());
app.use(express.json({ limit: '256kb' }));

app.get('/health', (req, res) => {
  refreshConfigIfChanged();
  res.json({
    ok: true,
    service: 'sdp-access-controller',
    config: {
      source: state.configSource,
      version: state.config.version,
      loadedAt: state.configLoadedAt,
      grantTtlSec: state.config.grantTtlSec,
      spaAdmissionTtlSec: state.config.spaAdmissionTtlSec
    },
    registeredGateways: state.gateways.size,
    registeredServices: state.services.size,
    configuredClients: state.config.clients.length,
    activeSpaAdmissions: state.spaAdmissions.size,
    spaUdpPort: SPA_UDP_PORT,
    ts: new Date().toISOString()
  });
});

app.get('/directory', (req, res) => {
  res.json({
    gateways: Array.from(state.gateways.values()),
    services: Array.from(state.services.values()).map((service) => ({
      serviceId: service.serviceId,
      name: service.name,
      entryGatewayId: service.entryGatewayId,
      internalGatewayId: service.internalGatewayId,
      pathPrefixes: service.pathPrefixes,
      requiresIdentity: service.requiresIdentity
    }))
  });
});

app.post('/register/gateway', requireRegistrationToken, (req, res) => {
  const body = req.body || {};
  if (typeof body.gatewayId !== 'string' || typeof body.url !== 'string') {
    return res.status(400).json({ ok: false, error: 'invalid_gateway_registration' });
  }

  const gateway = upsertGateway(body);
  return res.json({ ok: true, gateway });
});

app.post('/register/service', requireRegistrationToken, (req, res) => {
  const body = req.body || {};
  if (typeof body.serviceId !== 'string' || typeof body.originUrl !== 'string') {
    return res.status(400).json({ ok: false, error: 'invalid_service_registration' });
  }

  const service = upsertService(body);
  return res.json({ ok: true, service });
});

app.post('/connect', async (req, res) => {
  try {
    const body = req.body || {};
    const client = getClientRecord(body.clientId);
    if (!client || client.clientSecret !== body.clientSecret) {
      return res.status(403).json({ ok: false, error: 'invalid_client_credentials' });
    }

    cleanupExpiredState();
    const spaAdmission = state.spaAdmissions.get(client.clientId);
    if (!spaAdmission) {
      return res.status(403).json({ ok: false, error: 'missing_spa_admission' });
    }

    const service = state.services.get(body.serviceId);
    if (!service) {
      return res.status(404).json({ ok: false, error: 'unknown_service' });
    }

    const entryGateway = state.gateways.get(service.entryGatewayId);
    if (!entryGateway) {
      return res.status(503).json({ ok: false, error: 'entry_gateway_unavailable' });
    }

    const authz = await authorizeUserForService(service, body.requestedPath, body.method, body.userToken);
    if (!authz.allow) {
      return res.status(403).json({ ok: false, error: authz.reason });
    }

    const grant = createGrant(service, authz.identity, client.clientId);
    return res.json({
      ok: true,
      service: {
        serviceId: service.serviceId,
        name: service.name,
        requestedPath: body.requestedPath || null
      },
      connection: {
        gatewayId: entryGateway.gatewayId,
        gatewayType: entryGateway.gatewayType,
        gatewayUrl: entryGateway.url,
        clientCertificateCn: client.certificateCn
      },
      grantToken: grant.token,
      expiresAt: grant.expiresAt
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/authorize/gateway', (req, res) => {
  const body = req.body || {};
  if (typeof body.gatewayId !== 'string' || typeof body.grantToken !== 'string') {
    return res.status(400).json({ ok: false, error: 'invalid_gateway_authorization_request' });
  }

  const decision = authorizeGatewayGrant(body.grantToken, body.gatewayId, body.pathname, body.clientCertCn);
  return res.json(decision);
});

app.post('/authorize/client', (req, res) => {
  const body = req.body || {};
  if (typeof body.clientId !== 'string') {
    return res.status(400).json({ ok: false, error: 'invalid_client_authorization_request' });
  }

  const decision = validateSpaAdmission(body.clientId, typeof body.clientCertCn === 'string' ? body.clientCertCn : null);
  return res.json(decision);
});

const udpServer = dgram.createSocket('udp4');
udpServer.on('message', (buffer, rinfo) => {
  let packet;
  try {
    packet = JSON.parse(buffer.toString('utf8'));
  } catch (err) {
    return;
  }

  const result = validateSpaPacket(packet, rinfo.address);
  if (!result.ok) {
    console.warn(`[SDP-ACCESS] Rejected SPA packet from ${rinfo.address}: ${result.reason}`);
    return;
  }

  const ack = Buffer.from(JSON.stringify({
    ok: true,
    clientId: result.admission.clientId,
    admittedAt: result.admission.admittedAt,
    expiresAt: new Date(result.admission.expiresAtMs).toISOString()
  }), 'utf8');
  udpServer.send(ack, rinfo.port, rinfo.address, () => {});
  console.log(`[SDP-ACCESS] SPA admission active for ${result.admission.clientId} from ${rinfo.address}`);
});

udpServer.on('listening', () => {
  console.log(`[SDP-ACCESS] SPA UDP listener ready on 0.0.0.0:${SPA_UDP_PORT}`);
});

app.listen(PORT, '0.0.0.0', () => {
  refreshConfigIfChanged();
  console.log(`[SDP-ACCESS] Controller listening on http://0.0.0.0:${PORT}`);
});

udpServer.bind(SPA_UDP_PORT, '0.0.0.0');
setInterval(cleanupExpiredState, 10000);
