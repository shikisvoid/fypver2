const crypto = require('crypto');
const dgram = require('dgram');

function getArg(name, fallback = '') {
  const prefix = `--${name}=`;
  const match = process.argv.find((item) => item.startsWith(prefix));
  return match ? match.slice(prefix.length) : fallback;
}

const host = getArg('host', process.env.SDP_SPA_HOST || '127.0.0.1');
const port = parseInt(getArg('port', process.env.SDP_SPA_PORT || '62201'), 10);
const clientId = getArg('client-id', process.env.SDP_CLIENT_ID || '');
const spaSecret = getArg('spa-secret', process.env.SDP_SPA_SECRET || '');
const timeoutMs = parseInt(getArg('timeout-ms', process.env.SDP_SPA_TIMEOUT_MS || '2000'), 10);

if (!clientId || !spaSecret) {
  console.error('client-id and spa-secret are required');
  process.exit(1);
}

const timestamp = Math.floor(Date.now() / 1000);
const nonce = crypto.randomBytes(12).toString('hex');
const hmac = crypto.createHmac('sha256', spaSecret).update(`${clientId}.${timestamp}.${nonce}`).digest('hex');
const socket = dgram.createSocket('udp4');
const payload = Buffer.from(JSON.stringify({ clientId, timestamp, nonce, hmac }), 'utf8');
let complete = false;

function finish(code, text) {
  if (complete) return;
  complete = true;
  if (code === 0) {
    console.log(text);
  } else {
    console.error(text);
  }
  socket.close();
  process.exit(code);
}

socket.on('message', (message) => {
  try {
    const parsed = JSON.parse(message.toString('utf8'));
    finish(0, JSON.stringify(parsed));
  } catch (err) {
    finish(0, 'SPA admission acknowledged');
  }
});

socket.on('error', (err) => finish(1, err.message));

socket.send(payload, port, host, (err) => {
  if (err) {
    finish(1, err.message);
    return;
  }
  setTimeout(() => finish(0, 'SPA packet sent'), timeoutMs);
});
