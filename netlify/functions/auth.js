const crypto = require('crypto');

const { PORTAL_PASSWORD, AUTH_SECRET, AUTH_TTL_HOURS } = process.env;
const ttlHours = Number(AUTH_TTL_HOURS || 24);
const TOKEN_TTL_MS = (Number.isFinite(ttlHours) && ttlHours > 0 ? ttlHours : 24) * 60 * 60 * 1000;

function timingSafeEqual(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function parseCookies(header = '') {
  return header.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = rest.join('=');
    return acc;
  }, {});
}

function sign(expiresAt, secret) {
  return crypto.createHmac('sha256', secret).update(String(expiresAt)).digest('hex');
}

function verifyToken(token, secret) {
  if (!token) return false;
  const [expStr, signature] = token.split('.');
  const expiresAt = Number(expStr);
  if (!expStr || !signature || Number.isNaN(expiresAt) || expiresAt < Date.now()) return false;
  const expected = sign(expiresAt, secret);
  return timingSafeEqual(expected, signature);
}

function generateToken(secret) {
  const expiresAt = Date.now() + TOKEN_TTL_MS;
  const signature = sign(expiresAt, secret);
  return `${expiresAt}.${signature}`;
}

function response(statusCode, body = {}) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  };
}

exports.handler = async (event) => {
  const secret = AUTH_SECRET || PORTAL_PASSWORD;
  if (!secret || !PORTAL_PASSWORD) {
    console.error('Auth configuration manquante. PORTAL_PASSWORD (et idéalement AUTH_SECRET) doivent être définis.');
    return response(500, { error: 'Configuration manquante' });
  }

  // GET => vérifie la session existante
  if (event.httpMethod === 'GET') {
    const cookies = parseCookies(event.headers.cookie);
    const token = cookies.authToken;
    if (!verifyToken(token, secret)) {
      return response(401, { error: 'Non authentifié' });
    }
    return response(200, { ok: true });
  }

  if (event.httpMethod !== 'POST') {
    return response(405, { error: 'Méthode non autorisée' });
  }

  let password = '';
  try {
    const body = JSON.parse(event.body || '{}');
    password = body.password || '';
  } catch (e) {
    return response(400, { error: 'Requête invalide' });
  }

  const isValid = password && timingSafeEqual(password, PORTAL_PASSWORD);
  if (!isValid) {
    return response(401, { error: 'Mot de passe incorrect' });
  }

  const token = generateToken(secret);
  const cookie = [
    `authToken=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${Math.floor(TOKEN_TTL_MS / 1000)}`
  ].join('; ');

  return {
    ...response(200, { ok: true }),
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': cookie
    }
  };
};
