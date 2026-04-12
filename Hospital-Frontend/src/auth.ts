const API_BASE = ''

const ACCESS_KEY = 'hp_access_token'
const REFRESH_KEY = 'hp_refresh_token'
const SDP_GRANT_KEY = 'hp_sdp_grant_token'
const SDP_GRANT_EXPIRES_KEY = 'hp_sdp_grant_expires_at'

type TokenPair = { token?: string; refreshToken?: string; sdpGrantToken?: string; sdpGrantExpiresAt?: string }

export function setTokens({ token, refreshToken, sdpGrantToken, sdpGrantExpiresAt }: TokenPair) {
  if (token) localStorage.setItem(ACCESS_KEY, token)
  if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken)
  if (sdpGrantToken) localStorage.setItem(SDP_GRANT_KEY, sdpGrantToken)
  if (sdpGrantExpiresAt) localStorage.setItem(SDP_GRANT_EXPIRES_KEY, sdpGrantExpiresAt)
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY)
  localStorage.removeItem(REFRESH_KEY)
  localStorage.removeItem(SDP_GRANT_KEY)
  localStorage.removeItem(SDP_GRANT_EXPIRES_KEY)
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_KEY)
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY)
}

export function getSdpGrantToken(): string | null {
  const token = localStorage.getItem(SDP_GRANT_KEY)
  const expiresAt = localStorage.getItem(SDP_GRANT_EXPIRES_KEY)
  if (!token || !expiresAt) return token
  if (Date.now() > Date.parse(expiresAt) - 30000) return null
  return token
}

async function requestSdpGrant(token: string, requestedPath = '/api/patients', method = 'GET') {
  const res = await fetch(`${API_BASE}/sdp/connect`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ requestedPath, method })
  })
  const data = await res.json()
  if (!res.ok || !data.ok || !data.grantToken) {
    throw new Error(data.error || 'SDP grant request failed')
  }
  return { sdpGrantToken: data.grantToken, sdpGrantExpiresAt: data.expiresAt }
}

export async function buildSdpHeaders(input: string, method = 'GET'): Promise<Record<string, string>> {
  const token = getAccessToken()
  let sdpGrant = getSdpGrantToken()
  if (token && !sdpGrant) {
    const grant = await requestSdpGrant(token, input, method)
    setTokens({ sdpGrantToken: grant.sdpGrantToken, sdpGrantExpiresAt: grant.sdpGrantExpiresAt })
    sdpGrant = grant.sdpGrantToken
  }
  const headers: Record<string, string> = {}
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (sdpGrant) headers['x-sdp-grant'] = sdpGrant
  return headers
}

export async function fetchWithAuth(input: string, init: RequestInit = {}, retry = true): Promise<Response> {
  init.headers = init.headers || {}
  const method = init.method || 'GET'
  const sdpHeaders = await buildSdpHeaders(input, method)
  if (typeof init.headers !== 'string') {
    Object.assign(init.headers as Record<string, string>, sdpHeaders)
  }
  try {
    const res = await fetch(`${API_BASE}${input}`, init)
    if (res.status === 401 && retry) {
      const refresh = getRefreshToken()
      if (!refresh) return res
      const rres = await fetch(`${API_BASE}/api/token/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: refresh })
      })
      if (rres.ok) {
        const rdata = await rres.json()
        if (rdata.success && rdata.token) {
          const grant = await requestSdpGrant(rdata.token, input, method)
          setTokens({ token: rdata.token, refreshToken: rdata.refreshToken, ...grant })
          ;(init.headers as Record<string, string>)['Authorization'] = `Bearer ${rdata.token}`
          ;(init.headers as Record<string, string>)['x-sdp-grant'] = grant.sdpGrantToken
          return fetch(`${API_BASE}${input}`, init)
        }
      }
    }
    return res
  } catch (err) {
    throw err
  }
}

export async function login(email: string, password: string) {
  try {
    // Auth endpoints are proxied via Vite dev server
    console.log('Attempting login to /api/login')
    const res = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    console.log('Login response status:', res.status)
    const data = await res.json()
    console.log('Login response:', data)
    if (data.success && data.token) {
      const grant = await requestSdpGrant(data.token)
      data.sdpGrantToken = grant.sdpGrantToken
      data.sdpGrantExpiresAt = grant.sdpGrantExpiresAt
    }
    return data
  } catch (err) {
    console.error('Login error:', err)
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function verifyMfa(email: string, code: string) {
  try {
    // Auth endpoints are proxied via Vite dev server
    console.log('Attempting MFA verify to /api/mfa/verify')
    const res = await fetch(`${API_BASE}/api/mfa/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, code })
    })
    console.log('MFA verify response status:', res.status)
    const data = await res.json()
    console.log('MFA verify response:', data)
    if (data.success && data.token) {
      const grant = await requestSdpGrant(data.token)
      data.sdpGrantToken = grant.sdpGrantToken
      data.sdpGrantExpiresAt = grant.sdpGrantExpiresAt
    }
    return data
  } catch (err) {
    console.error('MFA verify error:', err)
    return { success: false, error: err instanceof Error ? err.message : 'Network error' }
  }
}

export async function fetchPatients() {
  const res = await fetchWithAuth(`/api/patients`, { method: 'GET' })
  return res.json()
}

export async function fetchAppointments() {
  const res = await fetchWithAuth(`/api/appointments`, { method: 'GET' })
  return res.json()
}

export async function fetchMe() {
  const res = await fetchWithAuth(`/api/me`, { method: 'GET' })
  return res.json()
}

export async function fetchAdminMfaSecret(email: string) {
  // Admin MFA secret is proxied via Vite dev server
  const res = await fetch(`${API_BASE}/api/admin/mfa/secret?email=${encodeURIComponent(email)}`, { method: 'GET' })
  return res.json()
}

export async function updatePatient(patientId: string, patientData: any) {
  const res = await fetchWithAuth(`/api/patients/${patientId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      first_name: patientData.name?.split(' ')[0] || patientData.firstName,
      last_name: patientData.name?.split(' ')[1] || patientData.lastName,
      dob: patientData.dob,
      gender: patientData.gender || 'Not specified',
      contact: patientData.phone || patientData.contact,
      insurance: patientData.insurance
    })
  })
  return res.json()
}

export async function createPatient(patientData: any) {
  const res = await fetchWithAuth('/api/patients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      first_name: patientData.name?.split(' ')[0] || '',
      last_name: patientData.name?.split(' ')[1] || '',
      dob: patientData.dob,
      gender: patientData.gender || 'Not specified',
      contact: patientData.phone || patientData.contact,
      insurance: patientData.insurance
    })
  })
  return res.json()
}

export async function deletePatient(patientId: string) {
  const res = await fetchWithAuth(`/api/patients/${patientId}`, {
    method: 'DELETE'
  })
  return res.json()
}

export async function createAppointment(appointmentData: any) {
  const res = await fetchWithAuth('/api/appointments', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      patient_id: appointmentData.patientId,
      doctor_id: appointmentData.doctorId,
      scheduled_at: new Date(`${appointmentData.date}T${appointmentData.time}`).toISOString(),
      appointment_type: appointmentData.appointmentType || 'consultation',
      notes: appointmentData.notes || appointmentData.reason
    })
  })
  return res.json()
}

export async function updateAppointment(appointmentId: string, appointmentData: any) {
  const res = await fetchWithAuth(`/api/appointments/${appointmentId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      patient_id: appointmentData.patientId,
      doctor_id: appointmentData.doctorId,
      scheduled_at: new Date(`${appointmentData.date}T${appointmentData.time}`).toISOString(),
      appointment_type: appointmentData.appointmentType,
      notes: appointmentData.notes,
      status: appointmentData.status
    })
  })
  return res.json()
}

export async function deleteAppointment(appointmentId: string) {
  const res = await fetchWithAuth(`/api/appointments/${appointmentId}`, {
    method: 'DELETE'
  })
  return res.json()
}

// Dashboard endpoints for different roles
export async function fetchDoctorDashboard() {
  const res = await fetchWithAuth('/api/doctor/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchReceptionistDashboard() {
  const res = await fetchWithAuth('/api/receptionist/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchNurseDashboard() {
  const res = await fetchWithAuth('/api/nurse/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchAccountantDashboard() {
  const res = await fetchWithAuth('/api/accountant/dashboard', { method: 'GET' })
  return res.json()
}

export async function fetchNotifications() {
  const res = await fetchWithAuth('/api/notifications', { method: 'GET' })
  return res.json()
}

export async function markNotificationRead(notificationId: string) {
  const res = await fetchWithAuth(`/api/notifications/${notificationId}/read`, {
    method: 'PUT'
  })
  return res.json()
}

export async function updateLabFees(billingId: string, labFees: number) {
  const res = await fetchWithAuth(`/api/billing/${billingId}/lab-fees`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ lab_fees: labFees })
  })
  return res.json()
}
