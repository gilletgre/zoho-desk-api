const fetch = require('node-fetch');

const {
  ZOHO_CLIENT_ID,
  ZOHO_CLIENT_SECRET,
  ZOHO_REFRESH_TOKEN,
  ZOHO_ORG_ID,
  ZOHO_ACCOUNT_ID,
  ZOHO_DC,
  AUTH_SECRET,
  PORTAL_PASSWORD
} = process.env;

const ACCOUNTS_BASE = `https://accounts.zoho.${ZOHO_DC}`;
const DESK_BASE = `https://desk.zoho.${ZOHO_DC}/api/v1`;

let cachedAccessToken = null;
let accessTokenExpiry = 0;

function parseCookies(header = '') {
  return header.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = rest.join('=');
    return acc;
  }, {});
}

function timingSafeEqual(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return require('crypto').timingSafeEqual(aBuf, bBuf);
}

function verifyAuth(event) {
  const secret = AUTH_SECRET || PORTAL_PASSWORD;
  if (!secret) return false;
  const cookies = parseCookies((event.headers && event.headers.cookie) || '');
  const token = cookies.authToken;
  if (!token) return false;
  const [expStr, signature] = token.split('.');
  const expiresAt = Number(expStr);
  if (!expStr || !signature || Number.isNaN(expiresAt) || expiresAt < Date.now()) {
    return false;
  }
  const expected = require('crypto').createHmac('sha256', secret).update(expStr).digest('hex');
  return timingSafeEqual(expected, signature);
}

function unauthorized() {
  return {
    statusCode: 401,
    body: JSON.stringify({ error: 'Non authentifié' }),
    headers: { "Access-Control-Allow-Origin": "*" }
  };
}

async function getAccessToken() {
  const now = Date.now();
  if (cachedAccessToken && now < accessTokenExpiry - 60000) {
    return cachedAccessToken;
  }

  const res = await fetch(`${ACCOUNTS_BASE}/oauth/v2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      refresh_token: ZOHO_REFRESH_TOKEN,
      client_id: ZOHO_CLIENT_ID,
      client_secret: ZOHO_CLIENT_SECRET,
      grant_type: "refresh_token"
    })
  });

  const data = await res.json();
  if (!res.ok) {
    console.error("Erreur OAuth (tickets):", data);
    throw new Error("Erreur OAuth Zoho");
  }

  cachedAccessToken = data.access_token;
  accessTokenExpiry = now + (data.expires_in || 3600) * 1000;
  return cachedAccessToken;
}

exports.handler = async (event) => {
  if (!verifyAuth(event)) {
    return unauthorized();
  }

  try {
    const token = await getAccessToken();

    const url = `${DESK_BASE}/accounts/${ZOHO_ACCOUNT_ID}/tickets`;

    const res = await fetch(url, {
      headers: {
        Authorization: `Zoho-oauthtoken ${token}`,
        orgId: ZOHO_ORG_ID
      }
    });

    const data = await res.json();
    if (!res.ok) {
      console.error("Erreur Zoho Desk (tickets):", data);
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Erreur Zoho Desk", details: data }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    const tickets = Array.isArray(data.data) ? data.data : data;

    return {
      statusCode: 200,
      body: JSON.stringify(tickets),
      headers: { "Access-Control-Allow-Origin": "*" }
    };
  } catch (e) {
    console.error(e);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: e.message }),
      headers: { "Access-Control-Allow-Origin": "*" }
    };
  }
};
