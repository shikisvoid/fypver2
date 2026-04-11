import crypto from 'node:crypto'
import dgram from 'node:dgram'
import fs from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const repoRoot = path.resolve(__dirname, '..')

const proxyTarget = process.env.VITE_PROXY_TARGET || process.env.SDP_GATEWAY_URL || 'https://127.0.0.1:8088'
const accessControllerUrl = process.env.SDP_ACCESS_CONTROLLER_URL || 'http://127.0.0.1:7001'
const spaHost = process.env.SDP_SPA_HOST || '127.0.0.1'
const spaPort = parseInt(process.env.SDP_SPA_PORT || '62201', 10)
const sdpClientId = process.env.SDP_CLIENT_ID || 'admin-laptop-01'
const sdpClientSecret = process.env.SDP_CLIENT_SECRET || 'admin_agent_secret_demo'
const sdpSpaSecret = process.env.SDP_SPA_SECRET || 'admin_spa_secret_demo'
const sdpServiceId = process.env.SDP_SERVICE_ID || 'hospital-backend-app'
const certDir = process.env.SDP_CERT_DIR || path.join(repoRoot, 'certs')
const caCertPath = process.env.SDP_CA_CERT || path.join(certDir, 'ca', 'ca.crt')
const clientCertPath = process.env.SDP_CLIENT_CERT || path.join(certDir, 'clients', `${sdpClientId}.crt`)
const clientKeyPath = process.env.SDP_CLIENT_KEY || path.join(certDir, 'clients', `${sdpClientId}.key`)

function readFileIfPresent(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath) : undefined
}

const tlsAgent = proxyTarget.startsWith('https:')
  ? new https.Agent({
      ca: readFileIfPresent(caCertPath),
      cert: readFileIfPresent(clientCertPath),
      key: readFileIfPresent(clientKeyPath),
      rejectUnauthorized: process.env.SDP_TLS_REJECT_UNAUTHORIZED === 'false' ? false : true
    })
  : undefined

let spaAdmissionExpiresAt = 0

function sendSpaKnock() {
  if (!sdpClientId || !sdpSpaSecret) {
    return Promise.reject(new Error('Missing SDP client id or SPA secret'))
  }

  return new Promise((resolve, reject) => {
    const timestamp = Math.floor(Date.now() / 1000)
    const nonce = crypto.randomBytes(12).toString('hex')
    const hmac = crypto.createHmac('sha256', sdpSpaSecret).update(`${sdpClientId}.${timestamp}.${nonce}`).digest('hex')
    const socket = dgram.createSocket('udp4')
    const payload = Buffer.from(JSON.stringify({ clientId: sdpClientId, timestamp, nonce, hmac }), 'utf8')
    const timeout = setTimeout(() => {
      socket.close()
      reject(new Error('SPA knock timed out'))
    }, 2000)

    socket.once('message', (message) => {
      clearTimeout(timeout)
      socket.close()
      try {
        const parsed = JSON.parse(message.toString('utf8'))
        spaAdmissionExpiresAt = parsed.expiresAt ? Date.parse(parsed.expiresAt) : Date.now() + 240000
      } catch {
        spaAdmissionExpiresAt = Date.now() + 240000
      }
      resolve()
    })

    socket.once('error', (err) => {
      clearTimeout(timeout)
      socket.close()
      reject(err)
    })

    socket.send(payload, spaPort, spaHost, (err) => {
      if (err) {
        clearTimeout(timeout)
        socket.close()
        reject(err)
      }
    })
  })
}

async function ensureSpaAdmission() {
  if (Date.now() + 30000 < spaAdmissionExpiresAt) return
  await sendSpaKnock()
}

function postJson(urlString, payload, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString)
    const body = JSON.stringify(payload)
    const client = url.protocol === 'https:' ? https : http
    const req = client.request({
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...headers
      },
      timeout: 5000
    }, (res) => {
      let raw = ''
      res.on('data', (chunk) => { raw += chunk })
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode || 500, body: JSON.parse(raw || '{}') })
        } catch (err) {
          reject(new Error(`Invalid JSON response: ${raw}`))
        }
      })
    })
    req.on('timeout', () => {
      req.destroy()
      reject(new Error('SDP controller request timed out'))
    })
    req.on('error', reject)
    req.write(body)
    req.end()
  })
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let raw = ''
    req.on('data', (chunk) => { raw += chunk })
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {})
      } catch (err) {
        reject(new Error('Invalid JSON request body'))
      }
    })
    req.on('error', reject)
  })
}

function writeJson(res, status, payload) {
  res.statusCode = status
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify(payload))
}

function sdpDevPlugin() {
  return {
    name: 'hospital-sdp-dev-proxy',
    configureServer(server) {
      server.middlewares.use('/sdp/connect', async (req, res) => {
        if (req.method !== 'POST') {
          writeJson(res, 405, { success: false, error: 'Method not allowed' })
          return
        }

        try {
          await ensureSpaAdmission()
          const body = await readRequestBody(req)
          const authHeader = req.headers.authorization || ''
          const tokenMatch = typeof authHeader === 'string' ? authHeader.match(/^Bearer\s+(.+)$/i) : null
          const userToken = body.userToken || (tokenMatch ? tokenMatch[1] : '')
          if (!userToken) {
            writeJson(res, 400, { success: false, error: 'Missing user token' })
            return
          }

          const grant = await postJson(`${accessControllerUrl}/connect`, {
            clientId: sdpClientId,
            clientSecret: sdpClientSecret,
            serviceId: body.serviceId || sdpServiceId,
            requestedPath: body.requestedPath || '/api/patients',
            method: body.method || 'GET',
            userToken
          })

          writeJson(res, grant.status, grant.body)
        } catch (err) {
          writeJson(res, 502, { success: false, error: err.message })
        }
      })

      server.middlewares.use('/api', async (req, res, next) => {
        try {
          await ensureSpaAdmission()
          next()
        } catch (err) {
          writeJson(res, 503, { success: false, error: `SPA admission failed: ${err.message}` })
        }
      })
    }
  }
}

const apiProxy = {
  target: proxyTarget,
  changeOrigin: true,
  secure: false,
  agent: tlsAgent,
  headers: {
    'x-sdp-client-id': sdpClientId
  }
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), sdpDevPlugin()],
  server: {
    host: '0.0.0.0',
    proxy: {
      '/api/login': apiProxy,
      '/api/mfa': apiProxy,
      '/api/token': apiProxy,
      '/api/logout': apiProxy,
      '/api/me': apiProxy,
      '/api/admin': apiProxy,
      '/api/patients': apiProxy,
      '/api/appointments': apiProxy,
      '/api/vitals': apiProxy,
      '/api/prescriptions': apiProxy,
      '/api/lab': apiProxy,
      '/api/billing': apiProxy,
      '/api/pharmacy': apiProxy,
      '/api/files': apiProxy,
      '/api/audit': apiProxy,
      '/api/monitoring': apiProxy,
      '/api/health': apiProxy,
      '/api/dashboard': apiProxy,
      '/api': apiProxy
    }
  }
})
