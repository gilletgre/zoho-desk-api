const fetch = require('node-fetch');

const {
  ZOHO_CLIENT_ID,
  ZOHO_CLIENT_SECRET,
  ZOHO_REFRESH_TOKEN,
  ZOHO_ORG_ID,
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
    console.error("Erreur OAuth (layoutFields):", data);
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
    const layoutId = event.queryStringParameters && event.queryStringParameters.layoutId;
    if (!layoutId) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing layoutId" }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    const token = await getAccessToken();
    // Récupère le layout complet puis extrait sections/champs.
    // On tente d'abord avec include=fields (documenté), puis fallback sans include.
    const urlWithFields = `${DESK_BASE}/layouts/${layoutId}?include=fields`;
    const urlFallback = `${DESK_BASE}/layouts/${layoutId}`;

    const res = await fetch(urlWithFields, {
      headers: {
        Authorization: `Zoho-oauthtoken ${token}`,
        orgId: ZOHO_ORG_ID
      }
    });

    let data;
    try {
      data = await res.json();
    } catch (parseErr) {
      console.error("Erreur parse JSON Zoho Desk (layoutFields include=fields):", parseErr);
      data = null;
    }

    // Fallback si erreur ou parse ko
    if (!res.ok || !data) {
      console.warn("Retry layoutFields without include");
      const res2 = await fetch(urlFallback, {
        headers: {
          Authorization: `Zoho-oauthtoken ${token}`,
          orgId: ZOHO_ORG_ID
        }
      });
      try {
        data = await res2.json();
      } catch (parseErr) {
        console.error("Erreur parse JSON Zoho Desk (layoutFields fallback):", parseErr);
        data = null;
      }
      if (!res2.ok || !data) {
        console.error("Erreur Zoho Desk (layoutFields):", { status: res2.status, data });
        return {
          statusCode: res2.status || 500,
          body: JSON.stringify({ error: "Erreur Zoho Desk", status: res2.status, details: data }),
          headers: { "Access-Control-Allow-Origin": "*" }
        };
      }
    }

    // On extrait les champs pour les mettre en regard de cf.*
    const sections = Array.isArray(data.sections) ? data.sections : [];
    const fields = sections.flatMap(sec => {
      const fs = Array.isArray(sec.fields) ? sec.fields : [];
      return fs.map(f => ({
        section: sec.name || sec.label || '',
        apiName: f.apiName || f.fieldName,
        displayName: f.displayName || f.label,
        dataType: f.dataType,
        required: !!f.required,
        visible: f.visible !== false
      }));
    });

    return {
      statusCode: 200,
      body: JSON.stringify({ layout: data, fields }),
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
