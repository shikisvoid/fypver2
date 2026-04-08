/**
 * Security Monitoring Service
 *
 * Detects security anomalies and suspicious patterns:
 * - Excessive failed login attempts (brute force)
 * - Multiple decrypt requests within short time
 * - Same user accessing many patients rapidly
 * - IP accessing multiple user accounts
 * - JWT-related security events
 *
 * PHASE 2 INTEGRATION: Sends security events to central telemetry API
 * and CRITICAL alerts to the Response Controller for automated response.
 */

const winstonLogger = require('./winstonLogger');
const http = require('http');

// Phase 2 Integration Configuration
const PHASE2_CONFIG = {
  TELEMETRY_HOST: process.env.TELEMETRY_HOST || '172.20.0.100',
  TELEMETRY_PORT: process.env.TELEMETRY_PORT || 9090,
  RESPONSE_CONTROLLER_HOST: process.env.RESPONSE_CONTROLLER_HOST || '172.20.0.130',
  RESPONSE_CONTROLLER_PORT: process.env.RESPONSE_CONTROLLER_PORT || 4100,
  HOST_ID: process.env.HOST_ID || 'hospital-backend',
  ENABLED: process.env.PHASE2_INTEGRATION !== 'false' // Enabled by default
};

const ML_INPUT_CONFIG = {
  HOST: process.env.ML_HOST || '172.20.0.140',
  PORT: parseInt(process.env.ML_PORT || '5000', 10),
  PATH: process.env.ML_PREDICT_PATH || '/predict',
  TIMEOUT_MS: parseInt(process.env.ML_TIMEOUT_MS || '3000', 10),
  ENABLED: process.env.ML_INPUT_ANALYSIS !== 'false'
};

const INPUT_ANALYSIS_CONFIG = {
  ENABLED: process.env.INPUT_THREAT_ANALYSIS !== 'false',
  MAX_DEPTH: parseInt(process.env.INPUT_THREAT_MAX_DEPTH || '4', 10),
  MAX_STRINGS: parseInt(process.env.INPUT_THREAT_MAX_STRINGS || '40', 10),
  MAX_TEXT_SAMPLE: parseInt(process.env.INPUT_THREAT_MAX_TEXT_SAMPLE || '2000', 10),
  BLOCK_ON_RULE_CRITICAL: process.env.INPUT_THREAT_BLOCK_ON_RULE_CRITICAL !== 'false',
  BLOCK_ON_HYBRID: process.env.INPUT_THREAT_BLOCK_ON_HYBRID !== 'false'
};

// Configuration thresholds
const THRESHOLDS = {
  MAX_LOGIN_FAILURES_PER_IP: 5,        // Per 15 minutes
  MAX_LOGIN_FAILURES_PER_USER: 3,       // Per 15 minutes
  MAX_DECRYPT_REQUESTS: 50,             // Per 5 minutes
  MAX_PATIENT_ACCESS_RATE: 20,          // Different patients per 5 minutes
  MAX_ACCOUNTS_PER_IP: 3,               // Different accounts from same IP per hour
  SUSPICIOUS_ACTIVITY_WINDOW: 15 * 60 * 1000, // 15 minutes in ms
  SHORT_WINDOW: 5 * 60 * 1000           // 5 minutes in ms
};

// In-memory tracking stores (would use Redis in production)
const trackingData = {
  loginFailuresByIP: new Map(),
  loginFailuresByUser: new Map(),
  decryptRequestsByUser: new Map(),
  patientAccessByUser: new Map(),
  accountsByIP: new Map(),
  blockedIPs: new Set(),
  alerts: [],
  recentInputAnalysis: []
};

const INPUT_PATTERN_RULES = [
  {
    type: 'SQLI_UNION',
    severity: 'critical',
    regex: /\bunion\b\s+\bselect\b/i,
    description: 'UNION-based SQL injection pattern'
  },
  {
    type: 'SQLI_TAUTOLOGY',
    severity: 'critical',
    regex: /(?:'|")?\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
    description: 'SQL tautology pattern'
  },
  {
    type: 'SQLI_STACKED_QUERY',
    severity: 'critical',
    regex: /;\s*(?:drop|truncate|delete|alter|insert|update|select)\b/i,
    description: 'Stacked SQL query pattern'
  },
  {
    type: 'XSS_SCRIPT_TAG',
    severity: 'critical',
    regex: /<\s*script\b/i,
    description: 'Script tag injection pattern'
  },
  {
    type: 'XSS_EVENT_HANDLER',
    severity: 'warning',
    regex: /\bon(?:error|load|click|mouseover|focus)\s*=/i,
    description: 'Inline event-handler injection pattern'
  },
  {
    type: 'XSS_JS_URI',
    severity: 'critical',
    regex: /javascript\s*:/i,
    description: 'JavaScript URI injection pattern'
  },
  {
    type: 'COMMAND_INJECTION',
    severity: 'critical',
    regex: /(?:\|\||&&|;)\s*(?:bash|sh|cmd|powershell|curl|wget|nc|netcat|whoami|ping|cat|type|dir)\b/i,
    description: 'Command injection pattern'
  },
  {
    type: 'PATH_TRAVERSAL',
    severity: 'critical',
    regex: /\.\.[\\/]/,
    description: 'Path traversal pattern'
  },
  {
    type: 'SSTI_TEMPLATE',
    severity: 'warning',
    regex: /(?:\{\{.*\}\}|<%.*%>)/,
    description: 'Template injection pattern'
  }
];

// Clean up old entries periodically
setInterval(() => {
  const now = Date.now();
  cleanupOldEntries(trackingData.loginFailuresByIP, THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW);
  cleanupOldEntries(trackingData.loginFailuresByUser, THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW);
  cleanupOldEntries(trackingData.decryptRequestsByUser, THRESHOLDS.SHORT_WINDOW);
  cleanupOldEntries(trackingData.patientAccessByUser, THRESHOLDS.SHORT_WINDOW);
  cleanupOldEntries(trackingData.accountsByIP, 60 * 60 * 1000); // 1 hour
  
  // Keep only last 1000 alerts
  if (trackingData.alerts.length > 1000) {
    trackingData.alerts = trackingData.alerts.slice(-1000);
  }
  if (trackingData.recentInputAnalysis.length > 200) {
    trackingData.recentInputAnalysis = trackingData.recentInputAnalysis.slice(-200);
  }
}, 60 * 1000); // Run every minute

function cleanupOldEntries(map, maxAge) {
  const now = Date.now();
  for (const [key, entries] of map.entries()) {
    const filtered = entries.filter(e => now - e.timestamp < maxAge);
    if (filtered.length === 0) {
      map.delete(key);
    } else {
      map.set(key, filtered);
    }
  }
}

// ================== TRACKING FUNCTIONS ==================

function trackLoginFailure(ipAddress, email) {
  const now = Date.now();

  // Track by IP
  if (!trackingData.loginFailuresByIP.has(ipAddress)) {
    trackingData.loginFailuresByIP.set(ipAddress, []);
  }
  trackingData.loginFailuresByIP.get(ipAddress).push({ timestamp: now, email });

  // Track by user
  if (email) {
    if (!trackingData.loginFailuresByUser.has(email)) {
      trackingData.loginFailuresByUser.set(email, []);
    }
    trackingData.loginFailuresByUser.get(email).push({ timestamp: now, ipAddress });
  }

  // ===== PHASE 2 INTEGRATION: Send login failure telemetry =====
  sendTelemetryToPhase2('LOGIN_FAILURE', {
    ipAddress,
    email: email || 'unknown',
    timestamp: new Date(now).toISOString()
  });

  // Check thresholds
  checkLoginThresholds(ipAddress, email);
}

function trackDecryptRequest(userId, resourceId) {
  const now = Date.now();
  if (!trackingData.decryptRequestsByUser.has(userId)) {
    trackingData.decryptRequestsByUser.set(userId, []);
  }
  trackingData.decryptRequestsByUser.get(userId).push({ timestamp: now, resourceId });
  
  // Check threshold
  const recentRequests = getRecentEntries(trackingData.decryptRequestsByUser.get(userId), THRESHOLDS.SHORT_WINDOW);
  if (recentRequests.length > THRESHOLDS.MAX_DECRYPT_REQUESTS) {
    createAlert('HIGH_DECRYPT_RATE', 'warning', { userId, count: recentRequests.length });
  }
}

function trackPatientAccess(userId, patientId) {
  const now = Date.now();
  if (!trackingData.patientAccessByUser.has(userId)) {
    trackingData.patientAccessByUser.set(userId, []);
  }
  trackingData.patientAccessByUser.get(userId).push({ timestamp: now, patientId });
  
  // Check for rapid access to many different patients
  const recentAccesses = getRecentEntries(trackingData.patientAccessByUser.get(userId), THRESHOLDS.SHORT_WINDOW);
  const uniquePatients = new Set(recentAccesses.map(a => a.patientId));
  
  if (uniquePatients.size > THRESHOLDS.MAX_PATIENT_ACCESS_RATE) {
    createAlert('RAPID_PATIENT_ACCESS', 'warning', { 
      userId, 
      uniquePatientsCount: uniquePatients.size,
      timeWindowMinutes: THRESHOLDS.SHORT_WINDOW / 60000 
    });
  }
}

function trackAccountAccess(ipAddress, userId) {
  const now = Date.now();
  if (!trackingData.accountsByIP.has(ipAddress)) {
    trackingData.accountsByIP.set(ipAddress, []);
  }
  trackingData.accountsByIP.get(ipAddress).push({ timestamp: now, userId });
  
  // Check for multiple accounts from same IP
  const recentAccesses = getRecentEntries(trackingData.accountsByIP.get(ipAddress), 60 * 60 * 1000);
  const uniqueAccounts = new Set(recentAccesses.map(a => a.userId));
  
  if (uniqueAccounts.size > THRESHOLDS.MAX_ACCOUNTS_PER_IP) {
    createAlert('MULTIPLE_ACCOUNTS_SAME_IP', 'warning', { 
      ipAddress, 
      accountCount: uniqueAccounts.size 
    });
  }
}

// ================== HELPER FUNCTIONS ==================

function getRecentEntries(entries, maxAge) {
  if (!entries) return [];
  const now = Date.now();
  return entries.filter(e => now - e.timestamp < maxAge);
}

function flattenInputStrings(value, pathPrefix = 'body', depth = 0, results = []) {
  if (depth > INPUT_ANALYSIS_CONFIG.MAX_DEPTH || results.length >= INPUT_ANALYSIS_CONFIG.MAX_STRINGS) {
    return results;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed) {
      results.push({ path: pathPrefix, value: trimmed });
    }
    return results;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      flattenInputStrings(item, `${pathPrefix}[${index}]`, depth + 1, results);
    });
    return results;
  }

  if (value && typeof value === 'object') {
    Object.entries(value).forEach(([key, nested]) => {
      flattenInputStrings(nested, `${pathPrefix}.${key}`, depth + 1, results);
    });
  }

  return results;
}

function findInputPatternMatches(strings) {
  const matches = [];

  for (const entry of strings) {
    for (const rule of INPUT_PATTERN_RULES) {
      if (!rule.regex.test(entry.value)) continue;
      matches.push({
        type: rule.type,
        severity: rule.severity,
        description: rule.description,
        field: entry.path,
        sample: entry.value.slice(0, 160)
      });
    }
  }

  return matches;
}

function buildMLTelemetryForInputAnalysis({ req, context = {}, strings, patternMatches }) {
  const joinedText = strings.map(item => item.value).join(' ').slice(0, INPUT_ANALYSIS_CONFIG.MAX_TEXT_SAMPLE);
  const lengths = strings.map(item => item.value.length);
  const totalLength = lengths.reduce((sum, value) => sum + value, 0);
  const maxLength = lengths.length ? Math.max(...lengths) : 0;
  const avgLength = lengths.length ? totalLength / lengths.length : 0;
  const specialCharCount = (joinedText.match(/[<>{}()[\];'"`$\\|&]/g) || []).length;
  const encodedSegmentCount = strings.filter(item => /(?:[A-Za-z0-9+/]{20,}={0,2}|%[0-9A-Fa-f]{2})/.test(item.value)).length;
  const criticalPatternCount = patternMatches.filter(match => match.severity === 'critical').length;

  const sqlRelated = patternMatches.filter(match => match.type.startsWith('SQLI_'));
  const dbAlerts = sqlRelated.map(match => ({
    type: 'DB_APP_INPUT_ANOMALY',
    severity: 'HIGH',
    table: context.entity || req.path,
    action: req.method,
    query: match.sample,
    field: match.field
  }));

  return {
    hostId: PHASE2_CONFIG.HOST_ID,
    ts: new Date().toISOString(),
    source: 'backend-input-threat-analyzer',
    eventType: 'APPLICATION_INPUT_ANALYSIS',
    userId: context.userId || 'anonymous',
    userRole: context.userRole || 'unknown',
    userEmail: context.userEmail || 'unknown',
    security: {
      method: req.method,
      path: req.path,
      ipAddress: context.ipAddress,
      suspiciousPatternCount: patternMatches.length,
      suspiciousPatterns: Array.from(new Set(patternMatches.map(match => match.type))),
      analyzedStringFields: strings.length
    },
    logs: patternMatches.map(match => ({
      type: 'SECURITY_EVENT',
      severity: match.severity.toUpperCase(),
      message: `${match.type} in ${match.field}: ${match.sample}`
    })),
    dbActivity: {
      alerts: dbAlerts,
      activeQueries: sqlRelated.length
    },
    net: {
      bytes_sent: totalLength,
      packets_per_sec: strings.length,
      duration: totalLength,
      avg_packet_size: avgLength,
      bytes_recv: specialCharCount,
      connRate: patternMatches.length
    },
    ml_features: {
      'Flow Bytes/s': totalLength,
      'Flow Duration': totalLength,
      'Total Fwd Packets': strings.length,
      'Total Backward Packets': patternMatches.length,
      'Fwd Packets Length Total': totalLength,
      'Bwd Packets Length Total': specialCharCount,
      'Packet Length Max': maxLength,
      'Packet Length Mean': avgLength,
      'Fwd Packet Length Max': maxLength,
      'Avg Fwd Segment Size': avgLength,
      'Fwd Header Length': Math.min(totalLength, 4096),
      'Bwd Header Length': Math.min(specialCharCount, 4096),
      'SYN Flag Count': patternMatches.length,
      'RST Flag Count': criticalPatternCount,
      'PSH Flag Count': encodedSegmentCount,
      'ACK Flag Count': strings.length + patternMatches.length,
      'FIN Flag Count': sqlRelated.length,
      'Protocol': Number(req.secure ? 17 : 6)
    }
  };
}

function callMLInputAnalysis(telemetry) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(telemetry);
    const options = {
      hostname: ML_INPUT_CONFIG.HOST,
      port: ML_INPUT_CONFIG.PORT,
      path: ML_INPUT_CONFIG.PATH,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: ML_INPUT_CONFIG.TIMEOUT_MS
    };

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(body || '{}'));
        } catch (err) {
          reject(new Error('ML input analysis parse error'));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('ML input analysis timeout')));
    req.write(postData);
    req.end();
  });
}

async function analyzeInputThreat(req, context = {}) {
  if (!INPUT_ANALYSIS_CONFIG.ENABLED) {
    return { skipped: true, reason: 'disabled' };
  }

  const strings = flattenInputStrings(context.payload ?? req.body);
  if (!strings.length) {
    return { skipped: true, reason: 'no-string-input' };
  }

  const patternMatches = findInputPatternMatches(strings);
  const hasCriticalRule = patternMatches.some(match => match.severity === 'critical');
  const ruleSeverity = hasCriticalRule ? 'critical' : (patternMatches.length ? 'warning' : 'info');
  const telemetry = buildMLTelemetryForInputAnalysis({ req, context, strings, patternMatches });

  let mlResult = null;
  if (ML_INPUT_CONFIG.ENABLED) {
    try {
      mlResult = await callMLInputAnalysis(telemetry);
    } catch (err) {
      console.warn(`[SecurityMonitor] ML input analysis unavailable: ${err.message}`);
    }
  }

  const mlTriggered = Boolean(mlResult && mlResult.is_anomaly);
  const hybridTriggered = Boolean(patternMatches.length && mlTriggered);
  const shouldBlock =
    (hasCriticalRule && INPUT_ANALYSIS_CONFIG.BLOCK_ON_RULE_CRITICAL) ||
    (hybridTriggered && INPUT_ANALYSIS_CONFIG.BLOCK_ON_HYBRID);

  const result = {
    analyzedAt: new Date().toISOString(),
    route: req.path,
    method: req.method,
    ipAddress: context.ipAddress,
    userId: context.userId || 'anonymous',
    userRole: context.userRole || 'unknown',
    userEmail: context.userEmail || 'unknown',
    stringsAnalyzed: strings.length,
    patternMatches,
    ruleTriggered: patternMatches.length > 0,
    ruleSeverity,
    mlTriggered,
    mlResult,
    hybridTriggered,
    shouldBlock
  };

  trackingData.recentInputAnalysis.push(result);

  if (patternMatches.length) {
    createAlert('SUSPICIOUS_INPUT_PATTERN', ruleSeverity, {
      route: req.path,
      method: req.method,
      ipAddress: context.ipAddress,
      userId: context.userId,
      userRole: context.userRole,
      userEmail: context.userEmail,
      patterns: Array.from(new Set(patternMatches.map(match => match.type))),
      fields: Array.from(new Set(patternMatches.map(match => match.field))).slice(0, 10)
    });
  }

  if (mlTriggered) {
    createAlert('ML_SUSPICIOUS_INPUT', mlResult.classification === 'Malicious' ? 'critical' : 'warning', {
      route: req.path,
      method: req.method,
      ipAddress: context.ipAddress,
      userId: context.userId,
      userRole: context.userRole,
      userEmail: context.userEmail,
      anomalyScore: mlResult.anomaly_score,
      classification: mlResult.classification,
      confidence: mlResult.confidence
    });
  }

  if (hybridTriggered) {
    createAlert('HYBRID_SUSPICIOUS_INPUT', 'critical', {
      route: req.path,
      method: req.method,
      ipAddress: context.ipAddress,
      userId: context.userId,
      userRole: context.userRole,
      userEmail: context.userEmail,
      patterns: Array.from(new Set(patternMatches.map(match => match.type))),
      anomalyScore: mlResult.anomaly_score,
      classification: mlResult.classification,
      confidence: mlResult.confidence
    });
  }

  return result;
}

function checkLoginThresholds(ipAddress, email) {
  const ipFailures = getRecentEntries(
    trackingData.loginFailuresByIP.get(ipAddress), 
    THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW
  );
  
  if (ipFailures.length >= THRESHOLDS.MAX_LOGIN_FAILURES_PER_IP) {
    createAlert('BRUTE_FORCE_IP', 'critical', { ipAddress, failureCount: ipFailures.length });
    trackingData.blockedIPs.add(ipAddress);
  }
  
  if (email) {
    const userFailures = getRecentEntries(
      trackingData.loginFailuresByUser.get(email),
      THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW
    );
    if (userFailures.length >= THRESHOLDS.MAX_LOGIN_FAILURES_PER_USER) {
      createAlert('BRUTE_FORCE_USER', 'warning', { email, failureCount: userFailures.length });
    }
  }
}

// ================== PHASE 2 INTEGRATION ==================

/**
 * Send telemetry to Phase 2 central collector
 */
function sendTelemetryToPhase2(eventType, data) {
  if (!PHASE2_CONFIG.ENABLED) return;

  const telemetry = {
    hostId: PHASE2_CONFIG.HOST_ID,
    ts: new Date().toISOString(),
    source: 'backend-security-monitor',
    eventType: eventType,
    security: data,
    // Add net field for traffic-analyzer compatibility if IP-related
    ...(data.ipAddress && { net: { src: data.ipAddress, dst: PHASE2_CONFIG.HOST_ID } })
  };

  const postData = JSON.stringify(telemetry);
  const options = {
    hostname: PHASE2_CONFIG.TELEMETRY_HOST,
    port: PHASE2_CONFIG.TELEMETRY_PORT,
    path: '/ingest/telemetry',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    },
    timeout: 5000
  };

  const req = http.request(options, (res) => {
    if (res.statusCode === 200) {
      console.log(`[Phase2] Telemetry sent: ${eventType}`);
    }
  });

  req.on('error', (err) => {
    // Silently fail - don't break main app if Phase 2 is down
    console.warn(`[Phase2] Telemetry send failed: ${err.message}`);
  });

  req.on('timeout', () => {
    req.destroy();
  });

  req.write(postData);
  req.end();
}

/**
 * Send CRITICAL alert to Phase 2 Response Controller for automated action
 */
function sendAlertToResponseController(alertType, data) {
  if (!PHASE2_CONFIG.ENABLED) return;

  const alert = {
    severity: 'CRITICAL',
    event: alertType,
    hostId: data.hostId || PHASE2_CONFIG.HOST_ID,
    ts: new Date().toISOString(),
    source: 'backend-security-monitor',
    details: data
  };

  const postData = JSON.stringify(alert);
  const options = {
    hostname: PHASE2_CONFIG.RESPONSE_CONTROLLER_HOST,
    port: PHASE2_CONFIG.RESPONSE_CONTROLLER_PORT,
    path: '/alert',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    },
    timeout: 5000
  };

  const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      try {
        const response = JSON.parse(body);
        if (response.action === 'isolate') {
          console.log(`[Phase2] 🚨 Response Controller isolated host: ${response.hostId}`);
        }
      } catch (e) { /* ignore parse errors */ }
    });
  });

  req.on('error', (err) => {
    console.warn(`[Phase2] Alert send to controller failed: ${err.message}`);
  });

  req.on('timeout', () => {
    req.destroy();
  });

  req.write(postData);
  req.end();
}

// ================== ALERT SYSTEM ==================

function createAlert(alertType, severity, data) {
  const alert = {
    id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
    type: alertType,
    severity, // 'info', 'warning', 'critical'
    timestamp: new Date().toISOString(),
    data,
    acknowledged: false
  };

  trackingData.alerts.push(alert);

  // Log to security log
  winstonLogger.logSecurity(`SECURITY_ALERT_${alertType}`, {
    alertId: alert.id,
    severity,
    details: data,
    ipAddress: data.ipAddress
  });

  // Console warning for critical alerts
  if (severity === 'critical') {
    console.error(`\x1b[31m[CRITICAL SECURITY ALERT]\x1b[0m ${alertType}:`, data);
  }

  // ===== PHASE 2 INTEGRATION =====
  // Send all alerts to telemetry
  sendTelemetryToPhase2(`SECURITY_ALERT_${alertType}`, {
    alertId: alert.id,
    alertType,
    severity,
    ...data
  });

  // Send CRITICAL alerts to Response Controller for automated action
  if (severity === 'critical') {
    sendAlertToResponseController(alertType, data);
  }

  return alert;
}

function getAlerts(filters = {}) {
  let alerts = trackingData.alerts;

  if (filters.severity) {
    alerts = alerts.filter(a => a.severity === filters.severity);
  }
  if (filters.type) {
    alerts = alerts.filter(a => a.type === filters.type);
  }
  if (filters.unacknowledged) {
    alerts = alerts.filter(a => !a.acknowledged);
  }
  if (filters.since) {
    const sinceDate = new Date(filters.since);
    alerts = alerts.filter(a => new Date(a.timestamp) > sinceDate);
  }

  return alerts.slice(-100); // Return last 100 matching
}

function acknowledgeAlert(alertId) {
  const alert = trackingData.alerts.find(a => a.id === alertId);
  if (alert) {
    alert.acknowledged = true;
    alert.acknowledgedAt = new Date().toISOString();
    return true;
  }
  return false;
}

// ================== IP BLOCKING ==================

function isIPBlocked(ipAddress) {
  return trackingData.blockedIPs.has(ipAddress);
}

function unblockIP(ipAddress) {
  trackingData.blockedIPs.delete(ipAddress);
  trackingData.loginFailuresByIP.delete(ipAddress);
}

function getBlockedIPs() {
  return Array.from(trackingData.blockedIPs);
}

// ================== JWT SECURITY EVENTS ==================

function logJWTExpired(userId, ipAddress) {
  winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.JWT_EXPIRED, {
    userId, ipAddress, details: { reason: 'Token expired' }
  });
}

function logJWTInvalid(ipAddress, reason) {
  winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.JWT_INVALID_SIGNATURE, {
    ipAddress, details: { reason }
  });

  // Track as potential attack
  trackLoginFailure(ipAddress, null);
}

function logUnauthorizedAccess(userId, role, resource, ipAddress) {
  winstonLogger.logSecurity(winstonLogger.SECURITY_EVENTS.UNAUTHORIZED_ACCESS_ATTEMPT, {
    userId, role, ipAddress, details: { resource }
  });
  createAlert('UNAUTHORIZED_ACCESS', 'warning', { userId, role, resource, ipAddress });
}

// ================== METRICS FOR PROMETHEUS ==================

function getSecurityMetrics() {
  return {
    blockedIPCount: trackingData.blockedIPs.size,
    activeAlerts: trackingData.alerts.filter(a => !a.acknowledged).length,
    criticalAlerts: trackingData.alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length,
    loginFailuresLast15min: Array.from(trackingData.loginFailuresByIP.values())
      .reduce((sum, entries) => sum + getRecentEntries(entries, THRESHOLDS.SUSPICIOUS_ACTIVITY_WINDOW).length, 0),
    recentInputAnalyses: trackingData.recentInputAnalysis.length,
    thresholds: THRESHOLDS
  };
}

function getPrometheusSecurityMetrics() {
  const metrics = getSecurityMetrics();
  const lines = [];

  lines.push('# HELP healthcare_blocked_ips_total Currently blocked IP addresses');
  lines.push('# TYPE healthcare_blocked_ips_total gauge');
  lines.push(`healthcare_blocked_ips_total ${metrics.blockedIPCount}`);

  lines.push('# HELP healthcare_security_alerts_active Active unacknowledged security alerts');
  lines.push('# TYPE healthcare_security_alerts_active gauge');
  lines.push(`healthcare_security_alerts_active ${metrics.activeAlerts}`);

  lines.push('# HELP healthcare_security_alerts_critical Critical security alerts');
  lines.push('# TYPE healthcare_security_alerts_critical gauge');
  lines.push(`healthcare_security_alerts_critical ${metrics.criticalAlerts}`);

  lines.push('# HELP healthcare_login_failures_15min Login failures in last 15 minutes');
  lines.push('# TYPE healthcare_login_failures_15min gauge');
  lines.push(`healthcare_login_failures_15min ${metrics.loginFailuresLast15min}`);

  lines.push('# HELP healthcare_input_analysis_recent_total Recent application input analyses retained in memory');
  lines.push('# TYPE healthcare_input_analysis_recent_total gauge');
  lines.push(`healthcare_input_analysis_recent_total ${metrics.recentInputAnalyses}`);

  return lines.join('\n');
}

module.exports = {
  // Tracking functions
  trackLoginFailure, trackDecryptRequest, trackPatientAccess, trackAccountAccess,

  // Alert functions
  createAlert, getAlerts, acknowledgeAlert,

  // IP blocking
  isIPBlocked, unblockIP, getBlockedIPs,

  // JWT security
  logJWTExpired, logJWTInvalid, logUnauthorizedAccess,

  // Metrics
  getSecurityMetrics, getPrometheusSecurityMetrics,

  // Hybrid input analysis
  analyzeInputThreat,

  // Phase 2 Integration
  sendTelemetryToPhase2, sendAlertToResponseController, PHASE2_CONFIG,

  // Config
  THRESHOLDS, trackingData, INPUT_ANALYSIS_CONFIG, ML_INPUT_CONFIG
};
