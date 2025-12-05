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
    console.error("Erreur OAuth (ticketConversations):", data);
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
    // include=all pour tenter de récupérer le contenu complet des messages
    let url = `${DESK_BASE}/tickets/${ticketId}/conversations?include=all`;

    let res = await fetch(url, {
      headers: {
        Authorization: `Zoho-oauthtoken ${token}`,
        orgId: ZOHO_ORG_ID
      }
    });

    let data = await res.json();
    // Fallback sans include si erreur 4xx
    if (!res.ok && res.status >= 400 && res.status < 500) {
      console.warn("Include=all rejected, retrying without include", { status: res.status, data });
      url = `${DESK_BASE}/tickets/${ticketId}/conversations`;
      res = await fetch(url, {
        headers: {
          Authorization: `Zoho-oauthtoken ${token}`,
          orgId: ZOHO_ORG_ID
        }
      });
      data = await res.json();
    }

    if (!res.ok) {
      console.error("Erreur Zoho Desk (conversations):", { status: res.status, data });
      return {
        statusCode: res.status,
        body: JSON.stringify({ error: "Erreur Zoho Desk", status: res.status, details: data }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    // Normalise pour le front
    const list = Array.isArray(data.data) ? data.data : data;

    // Tentative de récupérer le corps HTML/texte des conversations (premières uniquement pour limiter le coût)
    const withBodies = [];
    for (let i = 0; i < Math.min(list.length, 3); i++) {
      const conv = list[i];
      if (!conv || !conv.id) continue;
      try {
        // On tente plusieurs endpoints pour récupérer le body
        const candidates = [
          `${DESK_BASE}/conversations/${conv.id}?include=content,all`,
          `${DESK_BASE}/tickets/${ticketId}/conversations/${conv.id}?include=content,all`,
          `${DESK_BASE}/conversations/${conv.id}/content`
        ];

        let success = false;
        let detailData = null;
        let detailUrlTried = null;
        let lastStatus = null;
        let lastPayload = null;

        for (const detailUrl of candidates) {
          detailUrlTried = detailUrl;
          let detailRes;
          try {
            detailRes = await fetch(detailUrl, {
              headers: {
                Authorization: `Zoho-oauthtoken ${token}`,
                orgId: ZOHO_ORG_ID
              }
            });
          } catch (errFetch) {
            lastStatus = 'fetch-error';
            lastPayload = errFetch.message || String(errFetch);
            continue;
          }

          lastStatus = detailRes.status;
          try {
            detailData = await detailRes.json();
          } catch (parseErr) {
            detailData = { parseError: parseErr.message || 'Parse error' };
          }

          if (detailRes.ok && detailData) {
            withBodies.push({ ...detailData, detailUrl });
            success = true;
            break;
          } else {
            lastPayload = detailData;
          }
        }

        if (!success) {
          withBodies.push({ ...conv, error: "Detail fetch failed", lastStatus, detailUrl: detailUrlTried, details: lastPayload });
        }
      } catch (err) {
        withBodies.push({ ...conv, error: err.message || 'Detail fetch error' });
      }
    }

    // Si aucun body récupéré, on tente les threads comme fallback (contient parfois le contenu complet)
    let conversations = withBodies.length > 0 ? withBodies : list;

    if (withBodies.length === 0) {
      try {
        const threadsRes = await fetch(`${DESK_BASE}/tickets/${ticketId}/threads?include=all`, {
          headers: {
            Authorization: `Zoho-oauthtoken ${token}`,
            orgId: ZOHO_ORG_ID
          }
        });
        const threadsData = await threadsRes.json();
        conversations = Array.isArray(conversations) ? conversations : [conversations];
        conversations.push({ threads: threadsData, source: 'threads_fallback' });
      } catch (err) {
        conversations = Array.isArray(conversations) ? conversations : [conversations];
        conversations.push({ threadsError: err.message || 'threads fetch error' });
      }
    }

    return {
      statusCode: 200,
      body: JSON.stringify(conversations),
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
