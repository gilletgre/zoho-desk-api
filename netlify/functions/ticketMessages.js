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
let tokenPromise = null;

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

async function getAccessToken(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && cachedAccessToken && now < accessTokenExpiry - 60000) {
    return cachedAccessToken;
  }

  if (tokenPromise) {
    return tokenPromise;
  }

  tokenPromise = (async () => {
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
      console.error("Erreur OAuth (ticketMessages):", data);
      const err = new Error("Erreur OAuth Zoho");
      if (data && data.error === 'Access Denied' && /too many requests/i.test(data.error_description || '')) {
        err.rateLimited = true;
      }
      throw err;
    }

    cachedAccessToken = data.access_token;
    accessTokenExpiry = now + (data.expires_in || 3600) * 1000;
    return cachedAccessToken;
  })();

  try {
    return await tokenPromise;
  } finally {
    tokenPromise = null;
  }
}

exports.handler = async (event) => {
  if (!verifyAuth(event)) {
    return unauthorized();
  }

  try {
    const ticketId =
      event.queryStringParameters && event.queryStringParameters.id;
    if (!ticketId) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Missing ticket id" }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    const token = await getAccessToken();
    const urlWithInclude = `${DESK_BASE}/tickets/${ticketId}/messages?include=all`;
    const urlFallback = `${DESK_BASE}/tickets/${ticketId}/messages`;

    async function fetchMsgs(url) {
      const res = await fetch(url, {
        headers: {
          Authorization: `Zoho-oauthtoken ${token}`,
          orgId: ZOHO_ORG_ID
        }
      });
      const data = await res.json();
      return { res, data };
    }

    let { res, data } = await fetchMsgs(urlWithInclude);
    if (!res.ok && res.status >= 400 && res.status < 500) {
      console.warn("Include=all rejected (messages), retrying without include", { status: res.status, data });
      ({ res, data } = await fetchMsgs(urlFallback));
    }

    if (!res.ok) {
      // Sur certains tenants, /messages peut renvoyer 404 URL_NOT_FOUND: on renvoie juste une liste vide
      if (res.status === 404 && data && data.errorCode === 'URL_NOT_FOUND') {
        console.warn("Messages endpoint indisponible pour ce ticket, retour d'une liste vide");
        return {
          statusCode: 200,
          body: JSON.stringify([]),
          headers: { "Access-Control-Allow-Origin": "*" }
        };
      }

      console.error("Erreur Zoho Desk (messages):", { status: res.status, data });
      return {
        statusCode: res.status,
        body: JSON.stringify({ error: "Erreur Zoho Desk", status: res.status, details: data }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    const messages = Array.isArray(data.data) ? data.data : data;

    return {
      statusCode: 200,
      body: JSON.stringify(messages),
      headers: { "Access-Control-Allow-Origin": "*" }
    };
  } catch (e) {
    console.error(e);
    const statusCode = e.rateLimited ? 429 : 500;
    const message = e.rateLimited
      ? "Limite de requêtes Zoho atteinte, réessayez dans quelques instants."
      : e.message;
    return {
      statusCode,
      body: JSON.stringify({ error: message }),
      headers: { "Access-Control-Allow-Origin": "*" }
    };
  }
};
