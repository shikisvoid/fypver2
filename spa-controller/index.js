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
const STATE_FILE = process.env.SDP_STATE_FILE || path.join(__dirname, 'state.json');
const AUDIT_LOG_FILE = process.env.SDP_AUDIT_LOG_FILE || path.join(__dirname, 'audit.log');
const JWT_SECRET = readSecret('JWT_SECRET', 'sdp_phase2_shared_secret_change_me');
const GRANT_SIGNING_SECRET = readSecret('SDP_GRANT_SIGNING_SECRET', 'sdp_access_grant_secret_change_me');
const POLICY_ENGINE_URL = process.env.SDP_POLICY_ENGINE_URL || 'http://sdp-controller:7000';
const BIND_SPA_TO_SOURCE = process.env.SDP_BIND_SPA_TO_SOURCE !== 'false';

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
  isolatedSegments: new Map(),
  spaAdmissions: new Map(),
  issuedGrants: new Map(),
  usedSpaNonces: new Map()
};

function startsWithAny(pathname, prefixes) {
  return prefixes.some((prefix) => pathname === prefix || pathname.startsWith(prefix + '/'));
}

function readSecret(envName, demoFallback) {
  const value = process.env[envName];
  if (typeof value === 'string' && value.length > 0) return value;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(`${envName} is required in production`);
  }
  return demoFallback;
}

function parseEnvClients() {
  const raw = process.env.SDP_CLIENTS_JSON;
  if (typeof raw !== 'string' || raw.trim().length === 0) return null;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : null;
  } catch (err) {
    console.warn(`[SDP-ACCESS] Ignoring invalid SDP_CLIENTS_JSON: ${err.message}`);
    return null;
  }
}

function parsePositiveInt(value, fallback, minimum) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? Math.max(minimum, parsed) : fallback;
}

function normalizeIp(value) {
  if (typeof value !== 'string' || value.length === 0) return '';
  return value.replace(/^::ffff:/, '');
}

function normalizePathPrefixes(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((entry) => typeof entry === 'string' && entry.length > 0);
}

function ensureParentDir(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function mapToSortedArray(map) {
  return Array.from(map.values()).sort((a, b) => {
    const left = JSON.stringify(a);
    const right = JSON.stringify(b);
    return left.localeCompare(right);
  });
}

function savePersistentState() {
  ensureParentDir(STATE_FILE);
  const payload = {
    version: 1,
    updatedAt: new Date().toISOString(),
    gateways: mapToSortedArray(state.gateways),
    services: mapToSortedArray(state.services),
    isolatedSegments: mapToSortedArray(state.isolatedSegments),
    spaAdmissions: mapToSortedArray(state.spaAdmissions),
    issuedGrants: mapToSortedArray(state.issuedGrants),
    usedSpaNonces: Array.from(state.usedSpaNonces.entries()).map(([nonceKey, expiresAtMs]) => ({ nonceKey, expiresAtMs }))
  };
  const tempFile = `${STATE_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(payload, null, 2));
  fs.renameSync(tempFile, STATE_FILE);
}

function persistStateQuietly() {
  try {
    savePersistentState();
  } catch (err) {
    console.warn(`[SDP-ACCESS] Failed to persist state: ${err.message}`);
  }
}

function appendAuditEvent(eventType, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    eventType,
    details
  };
  try {
    ensureParentDir(AUDIT_LOG_FILE);
    fs.appendFileSync(AUDIT_LOG_FILE, `${JSON.stringify(entry)}\n`);
  } catch (err) {
    console.warn(`[SDP-ACCESS] Failed to append audit event ${eventType}: ${err.message}`);
  }
}

function loadPersistentState() {
  try {
    if (!fs.existsSync(STATE_FILE)) {
      return;
    }

    const parsed = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    const now = Date.now();

    state.gateways = new Map(
      (Array.isArray(parsed.gateways) ? parsed.gateways : [])
        .filter((gateway) => gateway && typeof gateway.gatewayId === 'string')
        .map((gateway) => [gateway.gatewayId, gateway])
    );
    state.services = new Map(
      (Array.isArray(parsed.services) ? parsed.services : [])
        .filter((service) => service && typeof service.serviceId === 'string')
        .map((service) => [service.serviceId, service])
    );
    state.isolatedSegments = new Map(
      (Array.isArray(parsed.isolatedSegments) ? parsed.isolatedSegments : [])
        .filter((segment) => segment && typeof segment.segmentId === 'string')
        .map((segment) => [segment.segmentId, segment])
    );
    state.spaAdmissions = new Map(
      (Array.isArray(parsed.spaAdmissions) ? parsed.spaAdmissions : [])
        .filter((admission) => admission && typeof admission.clientId === 'string' && Number.isFinite(admission.expiresAtMs) && admission.expiresAtMs > now)
        .map((admission) => [admission.clientId, admission])
    );
    state.issuedGrants = new Map(
      (Array.isArray(parsed.issuedGrants) ? parsed.issuedGrants : [])
        .filter((grant) => grant && typeof grant.jti === 'string' && Number.isFinite(grant.expiresAtMs) && grant.expiresAtMs > now)
        .map((grant) => [grant.jti, grant])
    );
    state.usedSpaNonces = new Map(
      (Array.isArray(parsed.usedSpaNonces) ? parsed.usedSpaNonces : [])
        .filter((entry) => entry && typeof entry.nonceKey === 'string' && Number.isFinite(entry.expiresAtMs) && entry.expiresAtMs > now)
        .map((entry) => [entry.nonceKey, entry.expiresAtMs])
    );
    console.log(`[SDP-ACCESS] Restored persistent state from ${STATE_FILE}`);
  } catch (err) {
    console.warn(`[SDP-ACCESS] Failed to restore state from ${STATE_FILE}: ${err.message}`);
  }
}

function normalizeConfig(raw) {
  const data = raw && typeof raw === 'object' ? raw : {};
  const clients = parseEnvClients() || (Array.isArray(data.clients) ? data.clients : []);

  return {
    version: typeof data.version === 'string' ? data.version : 'file-default',
    grantTtlSec: parsePositiveInt(process.env.SDP_GRANT_TTL_SEC || data.grantTtlSec, 600, 60),
    spaAdmissionTtlSec: parsePositiveInt(process.env.SDP_SPA_ADMISSION_TTL_SEC || data.spaAdmissionTtlSec, 300, 30),
    registrationToken: process.env.SDP_REGISTRATION_TOKEN || (typeof data.registrationToken === 'string' ? data.registrationToken : 'sdp_register_demo_token'),
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
  let changed = false;
  for (const [clientId, admission] of state.spaAdmissions.entries()) {
    if (!admission || admission.expiresAtMs <= now) {
      state.spaAdmissions.delete(clientId);
      changed = true;
    }
  }
  for (const [grantId, grant] of state.issuedGrants.entries()) {
    if (!grant || grant.expiresAtMs <= now) {
      state.issuedGrants.delete(grantId);
      changed = true;
    }
  }
  for (const [nonceKey, expiresAtMs] of state.usedSpaNonces.entries()) {
    if (expiresAtMs <= now) {
      state.usedSpaNonces.delete(nonceKey);
      changed = true;
    }
  }
  if (changed) {
    persistStateQuietly();
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

function validateSpaAdmission(clientId, clientCertCn, sourceIp) {
  cleanupExpiredState();
  const client = getClientRecord(clientId);
  if (!client) {
    appendAuditEvent('spa_admission_denied', { clientId, reason: 'unknown_client', clientCertCn, sourceIp });
    return { allow: false, reason: 'unknown_client' };
  }

  const admission = state.spaAdmissions.get(clientId);
  if (!admission) {
    appendAuditEvent('spa_admission_denied', { clientId, reason: 'missing_spa_admission', clientCertCn, sourceIp });
    return { allow: false, reason: 'missing_spa_admission' };
  }

  if (!clientCertCn) {
    appendAuditEvent('spa_admission_denied', { clientId, reason: 'missing_client_certificate_cn', sourceIp });
    return { allow: false, reason: 'missing_client_certificate_cn' };
  }

  if (client.certificateCn && client.certificateCn !== clientCertCn) {
    appendAuditEvent('spa_admission_denied', { clientId, reason: 'spa_client_certificate_mismatch', expectedCn: client.certificateCn, providedCn: clientCertCn, sourceIp });
    return { allow: false, reason: 'spa_client_certificate_mismatch' };
  }

  if (BIND_SPA_TO_SOURCE && sourceIp) {
    const admittedSource = normalizeIp(admission.remoteAddress);
    const requestSource = normalizeIp(sourceIp);
    if (admittedSource && requestSource && admittedSource !== requestSource) {
      appendAuditEvent('spa_admission_denied', { clientId, reason: 'spa_source_mismatch', admittedSource, requestSource, clientCertCn });
      return { allow: false, reason: 'spa_source_mismatch' };
    }
  }

  appendAuditEvent('spa_admission_validated', {
    clientId,
    clientCertCn,
    sourceIp,
    admittedAt: admission.admittedAt,
    expiresAt: new Date(admission.expiresAtMs).toISOString()
  });
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
  persistStateQuietly();
  appendAuditEvent('spa_admission_issued', {
    clientId,
    remoteAddress,
    admittedAt: admission.admittedAt,
    expiresAt: new Date(expiresAtMs).toISOString()
  });
  return admission;
}

function validateSpaPacket(packet, remoteAddress) {
  cleanupExpiredState();
  const clientId = typeof packet.clientId === 'string' ? packet.clientId : '';
  const timestamp = parseInt(packet.timestamp, 10);
  const nonce = typeof packet.nonce === 'string' ? packet.nonce : '';
  const hmac = typeof packet.hmac === 'string' ? packet.hmac.toLowerCase() : '';

  if (!clientId || !Number.isFinite(timestamp) || !nonce || !hmac) {
    appendAuditEvent('spa_knock_denied', { clientId, remoteAddress, reason: 'invalid_spa_packet' });
    return { ok: false, reason: 'invalid_spa_packet' };
  }

  const client = getClientRecord(clientId);
  if (!client || !client.spaSecret) {
    appendAuditEvent('spa_knock_denied', { clientId, remoteAddress, reason: 'unknown_spa_client' });
    return { ok: false, reason: 'unknown_spa_client' };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - timestamp) > 60) {
    appendAuditEvent('spa_knock_denied', { clientId, remoteAddress, reason: 'spa_clock_skew' });
    return { ok: false, reason: 'spa_clock_skew' };
  }

  const nonceKey = `${clientId}:${nonce}`;
  if (state.usedSpaNonces.has(nonceKey)) {
    appendAuditEvent('spa_knock_denied', { clientId, remoteAddress, reason: 'spa_replay_detected' });
    return { ok: false, reason: 'spa_replay_detected' };
  }

  const expectedHmac = createExpectedSpaHmac(client, timestamp, nonce);
  if (expectedHmac.length !== hmac.length) {
    appendAuditEvent('spa_knock_denied', { clientId, remoteAddress, reason: 'invalid_spa_hmac' });
    return { ok: false, reason: 'invalid_spa_hmac' };
  }

  const expectedBuffer = Buffer.from(expectedHmac, 'utf8');
  const providedBuffer = Buffer.from(hmac, 'utf8');
  if (!crypto.timingSafeEqual(expectedBuffer, providedBuffer)) {
    appendAuditEvent('spa_knock_denied', { clientId, remoteAddress, reason: 'invalid_spa_hmac' });
    return { ok: false, reason: 'invalid_spa_hmac' };
  }

  state.usedSpaNonces.set(nonceKey, Date.now() + (state.config.spaAdmissionTtlSec * 1000));
  persistStateQuietly();
  const admission = registerSpaAdmission(clientId, remoteAddress);
  return { ok: true, admission };
}

function requireRegistrationToken(req, res, next) {
  refreshConfigIfChanged();
  const provided = req.headers['x-registration-token'];
  if (provided !== state.config.registrationToken) {
    appendAuditEvent('registration_denied', {
      path: req.path,
      remoteAddress: req.ip || req.connection.remoteAddress || '',
      reason: 'invalid_registration_token'
    });
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
  persistStateQuietly();
  appendAuditEvent('gateway_registered', gateway);
  return gateway;
}

function upsertService(body) {
  const service = {
    serviceId: body.serviceId,
    name: typeof body.name === 'string' ? body.name : body.serviceId,
    segmentId: typeof body.segmentId === 'string' && body.segmentId.trim().length > 0 ? body.segmentId.trim() : body.serviceId,
    entryGatewayId: typeof body.entryGatewayId === 'string' ? body.entryGatewayId : null,
    internalGatewayId: typeof body.internalGatewayId === 'string' ? body.internalGatewayId : null,
    originUrl: typeof body.originUrl === 'string' ? body.originUrl : null,
    pathPrefixes: normalizePathPrefixes(body.pathPrefixes),
    requiresIdentity: body.requiresIdentity !== false,
    registeredAt: new Date().toISOString()
  };
  state.services.set(service.serviceId, service);
  persistStateQuietly();
  appendAuditEvent('service_registered', service);
  return service;
}

function getSegmentIsolation(segmentId) {
  if (typeof segmentId !== 'string' || segmentId.length === 0) {
    return null;
  }
  return state.isolatedSegments.get(segmentId) || null;
}

function isolateSegmentAccess({ segmentId, serviceId = null, reason = 'segment_isolated' }) {
  const normalizedSegmentId = typeof segmentId === 'string' && segmentId.trim().length > 0 ? segmentId.trim() : null;
  const normalizedServiceId = typeof serviceId === 'string' && serviceId.trim().length > 0 ? serviceId.trim() : null;

  if (!normalizedSegmentId) {
    return { skipped: true, reason: 'segmentId_required', revokedGrants: 0, affectedServices: [] };
  }

  const affectedServices = Array.from(state.services.values())
    .filter((service) => service.segmentId === normalizedSegmentId && (!normalizedServiceId || service.serviceId === normalizedServiceId))
    .map((service) => service.serviceId);

  let revokedGrants = 0;
  for (const grant of state.issuedGrants.values()) {
    if (affectedServices.includes(grant.serviceId) && !grant.revokedAt) {
      grant.revokedAt = new Date().toISOString();
      grant.revokeReason = `segment_isolated:${normalizedSegmentId}:${reason}`;
      revokedGrants += 1;
    }
  }

  const isolation = {
    segmentId: normalizedSegmentId,
    serviceId: normalizedServiceId,
    reason,
    isolatedAt: new Date().toISOString(),
    affectedServices
  };

  state.isolatedSegments.set(normalizedSegmentId, isolation);
  persistStateQuietly();
  appendAuditEvent('segment_isolated', isolation);
  return { ok: true, revokedGrants, affectedServices, isolation };
}

function releaseSegmentAccess({ segmentId, reason = 'manual_release' }) {
  const normalizedSegmentId = typeof segmentId === 'string' && segmentId.trim().length > 0 ? segmentId.trim() : null;
  if (!normalizedSegmentId) {
    return { skipped: true, reason: 'segmentId_required' };
  }

  const existing = state.isolatedSegments.get(normalizedSegmentId);
  if (!existing) {
    return { ok: true, released: false, segmentId: normalizedSegmentId };
  }

  state.isolatedSegments.delete(normalizedSegmentId);
  persistStateQuietly();
  appendAuditEvent('segment_released', {
    segmentId: normalizedSegmentId,
    reason,
    releasedAt: new Date().toISOString(),
    previousIsolation: existing
  });
  return { ok: true, released: true, segmentId: normalizedSegmentId };
}

async function authorizeUserForService(service, pathname, method, userToken) {
  const activeIsolation = getSegmentIsolation(service.segmentId);
  if (activeIsolation) {
    appendAuditEvent('grant_denied', {
      serviceId: service.serviceId,
      pathname,
      method,
      segmentId: service.segmentId,
      reason: 'segment_isolated'
    });
    return { allow: false, reason: 'segment_isolated' };
  }

  if (!service.requiresIdentity) {
    return { allow: true, reason: 'service_public' };
  }

  if (!userToken) {
    appendAuditEvent('grant_denied', { serviceId: service.serviceId, pathname, method, reason: 'missing_user_token' });
    return { allow: false, reason: 'missing_user_token' };
  }

  let identity;
  try {
    identity = jwt.verify(userToken, JWT_SECRET);
  } catch (err) {
    appendAuditEvent('grant_denied', { serviceId: service.serviceId, pathname, method, reason: 'invalid_user_token' });
    return { allow: false, reason: 'invalid_user_token' };
  }

  const targetPath = typeof pathname === 'string' && pathname.length > 0
    ? pathname
    : (service.pathPrefixes[0] || '/');

  if (service.pathPrefixes.length > 0 && !startsWithAny(targetPath, service.pathPrefixes)) {
    appendAuditEvent('grant_denied', { serviceId: service.serviceId, pathname: targetPath, method, reason: 'path_outside_service_scope' });
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
    appendAuditEvent('policy_denied', {
      serviceId: service.serviceId,
      pathname: targetPath,
      method,
      reason: result.body.reason || 'policy_denied',
      user: identity ? { email: identity.email, role: identity.role } : null
    });
    return { allow: false, reason: result.body.reason || 'policy_denied', identity };
  }

  return { allow: true, reason: result.body.reason || 'policy_allow', identity };
}

function createGrant(service, identity, clientId) {
  const client = getClientRecord(clientId);
  const nowSec = Math.floor(Date.now() / 1000);
  const expiresAtSec = nowSec + state.config.grantTtlSec;
  const grantId = crypto.randomUUID();
  const payload = {
    iss: 'hospital-sdp-access-controller',
    jti: grantId,
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

  const token = jwt.sign(payload, GRANT_SIGNING_SECRET);
  const grant = {
    jti: grantId,
    token,
    clientId,
    serviceId: service.serviceId,
    entryGatewayId: service.entryGatewayId,
    internalGatewayId: service.internalGatewayId,
    pathPrefixes: service.pathPrefixes,
    clientCertCn: client ? client.certificateCn : clientId,
    user: payload.user || null,
    issuedAt: new Date(nowSec * 1000).toISOString(),
    expiresAt: new Date(expiresAtSec * 1000).toISOString(),
    expiresAtMs: expiresAtSec * 1000,
    revokedAt: null,
    revokeReason: null
  };
  state.issuedGrants.set(grantId, grant);
  persistStateQuietly();
  appendAuditEvent('grant_issued', {
    grantId,
    clientId,
    serviceId: service.serviceId,
    user: grant.user,
    expiresAt: grant.expiresAt
  });
  return {
    token,
    expiresAt: grant.expiresAt,
    grantId
  };
}

function authorizeGatewayGrant(grantToken, gatewayId, pathname, clientCertCn) {
  let payload;
  try {
    payload = jwt.verify(grantToken, GRANT_SIGNING_SECRET);
  } catch (err) {
    appendAuditEvent('gateway_authorization_denied', { gatewayId, pathname, clientCertCn, reason: 'invalid_grant_token' });
    return { allow: false, reason: 'invalid_grant_token' };
  }

  const persistedGrant = payload && payload.jti ? state.issuedGrants.get(payload.jti) : null;
  if (!persistedGrant) {
    appendAuditEvent('gateway_authorization_denied', {
      gatewayId,
      pathname,
      clientCertCn,
      serviceId: payload.serviceId,
      grantId: payload.jti || null,
      reason: 'unknown_grant'
    });
    return { allow: false, reason: 'unknown_grant' };
  }

  if (persistedGrant.revokedAt) {
    appendAuditEvent('gateway_authorization_denied', {
      gatewayId,
      pathname,
      clientCertCn,
      serviceId: payload.serviceId,
      grantId: payload.jti,
      reason: 'grant_revoked',
      revokeReason: persistedGrant.revokeReason
    });
    return { allow: false, reason: 'grant_revoked' };
  }

  const service = state.services.get(payload.serviceId);
  if (!service) {
    appendAuditEvent('gateway_authorization_denied', { gatewayId, pathname, clientCertCn, serviceId: payload.serviceId, grantId: payload.jti, reason: 'unknown_service' });
    return { allow: false, reason: 'unknown_service' };
  }

  const activeIsolation = getSegmentIsolation(service.segmentId);
  if (activeIsolation) {
    appendAuditEvent('gateway_authorization_denied', {
      gatewayId,
      pathname,
      clientCertCn,
      serviceId: payload.serviceId,
      grantId: payload.jti,
      segmentId: service.segmentId,
      reason: 'segment_isolated'
    });
    return { allow: false, reason: 'segment_isolated' };
  }

  const entryGatewayId = payload.entryGatewayId;
  const internalGatewayId = payload.internalGatewayId;
  const isGatewayAllowed = gatewayId === entryGatewayId || gatewayId === internalGatewayId;
  if (!isGatewayAllowed) {
    appendAuditEvent('gateway_authorization_denied', { gatewayId, pathname, clientCertCn, serviceId: payload.serviceId, grantId: payload.jti, reason: 'gateway_not_authorized_for_grant' });
    return { allow: false, reason: 'gateway_not_authorized_for_grant' };
  }

  if (Array.isArray(payload.pathPrefixes) && payload.pathPrefixes.length > 0 && pathname && !startsWithAny(pathname, payload.pathPrefixes)) {
    appendAuditEvent('gateway_authorization_denied', { gatewayId, pathname, clientCertCn, serviceId: payload.serviceId, grantId: payload.jti, reason: 'path_not_authorized_for_service' });
    return { allow: false, reason: 'path_not_authorized_for_service' };
  }

  if (clientCertCn && payload.clientCertCn && clientCertCn !== payload.clientCertCn) {
    appendAuditEvent('gateway_authorization_denied', { gatewayId, pathname, clientCertCn, expectedCn: payload.clientCertCn, serviceId: payload.serviceId, grantId: payload.jti, reason: 'client_certificate_mismatch' });
    return { allow: false, reason: 'client_certificate_mismatch' };
  }

  let upstreamUrl = service.originUrl;
  let nextGatewayId = null;
  if (gatewayId === entryGatewayId && internalGatewayId) {
    const internalGateway = state.gateways.get(internalGatewayId);
    if (!internalGateway) {
      appendAuditEvent('gateway_authorization_denied', { gatewayId, pathname, clientCertCn, serviceId: payload.serviceId, grantId: payload.jti, reason: 'internal_gateway_unavailable' });
      return { allow: false, reason: 'internal_gateway_unavailable' };
    }
    upstreamUrl = internalGateway.url;
    nextGatewayId = internalGateway.gatewayId;
  }

  appendAuditEvent('gateway_authorized', {
    gatewayId,
    pathname,
    clientCertCn,
    serviceId: service.serviceId,
    grantId: payload.jti,
    nextGatewayId,
    user: payload.user || null
  });
  return {
    allow: true,
    reason: 'grant_valid',
    serviceId: service.serviceId,
    upstreamUrl,
    nextGatewayId,
    user: payload.user || null
  };
}

function revokeAccess({ clientId = null, userEmail = null, reason = 'manual_revoke' }) {
  cleanupExpiredState();
  const normalizedClientId = typeof clientId === 'string' && clientId.trim() && clientId.trim().toLowerCase() !== 'unknown'
    ? clientId.trim()
    : null;
  const normalizedUserEmail = typeof userEmail === 'string' && userEmail.trim() && userEmail.trim().toLowerCase() !== 'unknown'
    ? userEmail.trim()
    : null;
  let revokedAdmissions = 0;
  let revokedGrants = 0;

  if (!normalizedClientId && !normalizedUserEmail) {
    return { skipped: true, revokedAdmissions, revokedGrants };
  }

  if (normalizedClientId && state.spaAdmissions.has(normalizedClientId)) {
    state.spaAdmissions.delete(normalizedClientId);
    revokedAdmissions += 1;
  }

  for (const grant of state.issuedGrants.values()) {
    const matchesClient = normalizedClientId ? grant.clientId === normalizedClientId : false;
    const matchesUser = normalizedUserEmail ? grant.user && grant.user.email === normalizedUserEmail : false;
    if ((matchesClient || matchesUser) && !grant.revokedAt) {
      grant.revokedAt = new Date().toISOString();
      grant.revokeReason = reason;
      revokedGrants += 1;
    }
  }

  if (revokedAdmissions > 0 || revokedGrants > 0) {
    persistStateQuietly();
  }

  if (revokedAdmissions > 0 || revokedGrants > 0) {
    appendAuditEvent('access_revoked', {
      clientId: normalizedClientId,
      userEmail: normalizedUserEmail,
      reason,
      revokedAdmissions,
      revokedGrants
    });
  }
  return { revokedAdmissions, revokedGrants };
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
    activeIssuedGrants: Array.from(state.issuedGrants.values()).filter((grant) => !grant.revokedAt).length,
    isolatedSegments: Array.from(state.isolatedSegments.values()),
    spaUdpPort: SPA_UDP_PORT,
    bindSpaToSource: BIND_SPA_TO_SOURCE,
    stateFile: STATE_FILE,
    auditLogFile: AUDIT_LOG_FILE,
    ts: new Date().toISOString()
  });
});

app.get('/directory', (req, res) => {
  res.json({
    gateways: Array.from(state.gateways.values()),
    services: Array.from(state.services.values()).map((service) => ({
      serviceId: service.serviceId,
      name: service.name,
      segmentId: service.segmentId,
      entryGatewayId: service.entryGatewayId,
      internalGatewayId: service.internalGatewayId,
      pathPrefixes: service.pathPrefixes,
      requiresIdentity: service.requiresIdentity,
      isolated: Boolean(getSegmentIsolation(service.segmentId))
    }))
  });
});

app.get('/audit/recent', requireRegistrationToken, (req, res) => {
  try {
    const limit = parsePositiveInt(req.query.limit, 50, 1);
    if (!fs.existsSync(AUDIT_LOG_FILE)) {
      return res.json({ ok: true, events: [] });
    }
    const lines = fs.readFileSync(AUDIT_LOG_FILE, 'utf8')
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-limit)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch (err) {
          return { ts: new Date().toISOString(), eventType: 'audit_parse_error', details: { line } };
        }
      });
    return res.json({ ok: true, events: lines });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
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
      appendAuditEvent('grant_denied', { clientId: body.clientId || null, serviceId: body.serviceId || null, reason: 'invalid_client_credentials' });
      return res.status(403).json({ ok: false, error: 'invalid_client_credentials' });
    }

    cleanupExpiredState();
    const spaAdmission = state.spaAdmissions.get(client.clientId);
    if (!spaAdmission) {
      appendAuditEvent('grant_denied', { clientId: client.clientId, serviceId: body.serviceId || null, reason: 'missing_spa_admission' });
      return res.status(403).json({ ok: false, error: 'missing_spa_admission' });
    }

    const service = state.services.get(body.serviceId);
    if (!service) {
      appendAuditEvent('grant_denied', { clientId: client.clientId, serviceId: body.serviceId || null, reason: 'unknown_service' });
      return res.status(404).json({ ok: false, error: 'unknown_service' });
    }

    const entryGateway = state.gateways.get(service.entryGatewayId);
    if (!entryGateway) {
      appendAuditEvent('grant_denied', { clientId: client.clientId, serviceId: body.serviceId, reason: 'entry_gateway_unavailable' });
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
      grantId: grant.grantId,
      expiresAt: grant.expiresAt
    });
  } catch (err) {
    appendAuditEvent('grant_error', { reason: err.message });
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

  const decision = validateSpaAdmission(
    body.clientId,
    typeof body.clientCertCn === 'string' ? body.clientCertCn : null,
    typeof body.sourceIp === 'string' ? body.sourceIp : null
  );
  return res.json(decision);
});

app.post('/admin/revoke', requireRegistrationToken, (req, res) => {
  const body = req.body || {};
  const clientId = typeof body.clientId === 'string' && body.clientId.length > 0 ? body.clientId : null;
  const userEmail = typeof body.userEmail === 'string' && body.userEmail.length > 0 ? body.userEmail : null;
  const reason = typeof body.reason === 'string' && body.reason.length > 0 ? body.reason : 'manual_revoke';

  if (!clientId && !userEmail) {
    return res.status(400).json({ ok: false, error: 'clientId_or_userEmail_required' });
  }

  const result = revokeAccess({ clientId, userEmail, reason });
  return res.json({ ok: true, ...result });
});

app.post('/admin/isolate-segment', requireRegistrationToken, (req, res) => {
  const body = req.body || {};
  const serviceId = typeof body.serviceId === 'string' && body.serviceId.length > 0 ? body.serviceId : null;
  const segmentId = typeof body.segmentId === 'string' && body.segmentId.length > 0
    ? body.segmentId
    : (serviceId && state.services.get(serviceId) ? state.services.get(serviceId).segmentId : null);
  const reason = typeof body.reason === 'string' && body.reason.length > 0 ? body.reason : 'manual_segment_isolation';

  if (!segmentId) {
    return res.status(400).json({ ok: false, error: 'segmentId_or_serviceId_required' });
  }

  const result = isolateSegmentAccess({ segmentId, serviceId, reason });
  return res.json(result);
});

app.post('/admin/release-segment', requireRegistrationToken, (req, res) => {
  const body = req.body || {};
  const segmentId = typeof body.segmentId === 'string' && body.segmentId.length > 0 ? body.segmentId : null;
  const reason = typeof body.reason === 'string' && body.reason.length > 0 ? body.reason : 'manual_segment_release';

  if (!segmentId) {
    return res.status(400).json({ ok: false, error: 'segmentId_required' });
  }

  const result = releaseSegmentAccess({ segmentId, reason });
  return res.json(result);
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
  loadPersistentState();
  console.log(`[SDP-ACCESS] Controller listening on http://0.0.0.0:${PORT}`);
});

udpServer.bind(SPA_UDP_PORT, '0.0.0.0');
setInterval(cleanupExpiredState, 10000);
