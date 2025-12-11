const fetch = require('node-fetch');
const FormData = require('form-data');

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
    headers: {
      "Access-Control-Allow-Origin": "https://zohodeskclabots.netlify.app",
      "Access-Control-Allow-Credentials": "true"
    }
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
    console.error("Erreur OAuth (uploadImage):", data);
    throw new Error("Erreur OAuth Zoho");
  }

  cachedAccessToken = data.access_token;
  accessTokenExpiry = now + (data.expires_in || 3600) * 1000;
  return cachedAccessToken;
}

exports.handler = async (event) => {
  console.log('uploadImage - Headers reçus:', JSON.stringify(event.headers));
  console.log('uploadImage - Cookies:', event.headers?.cookie || 'Aucun cookie');

  if (!verifyAuth(event)) {
    console.log('uploadImage - Échec de l\'authentification');
    return unauthorized();
  }

  console.log('uploadImage - Authentification réussie');

  // Vérifier que c'est une requête POST
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Méthode non autorisée. Utilisez POST.' }),
      headers: { "Access-Control-Allow-Origin": "*" }
    };
  }

  try {
    // Parser le corps de la requête qui devrait contenir l'image
    const body = JSON.parse(event.body);
    const ticketId = body.ticketId;
    const imageData = body.imageData; // Base64 encoded image

    if (!ticketId || !imageData) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Paramètres manquants: ticketId et imageData sont requis" }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    const token = await getAccessToken();

    // Upload de l'image vers Zoho Desk
    const uploadUrl = `${DESK_BASE}/tickets/${ticketId}/attachments`;

    // Convertir l'image base64 en buffer
    const base64Data = imageData.replace(/^data:image\/\w+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');

    const form = new FormData();
    form.append('file', buffer, {
      filename: `feedback-image-${Date.now()}.jpg`,
      contentType: 'image/jpeg'
    });

    const uploadRes = await fetch(uploadUrl, {
      method: 'POST',
      headers: {
        Authorization: `Zoho-oauthtoken ${token}`,
        orgId: ZOHO_ORG_ID,
        ...form.getHeaders()
      },
      body: form
    });

    if (!uploadRes.ok) {
      const errorData = await uploadRes.json();
      console.error("Erreur lors de l'upload de l'image:", errorData);
      throw new Error("Impossible d'uploader l'image");
    }

    const responseData = await uploadRes.json();

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: 'Image uploadée avec succès',
        ticketId: ticketId,
        attachment: responseData
      }),
      headers: {
        "Access-Control-Allow-Origin": "https://zohodeskclabots.netlify.app",
        "Access-Control-Allow-Credentials": "true"
      }
    };

  } catch (e) {
    console.error(e);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: e.message }),
      headers: {
        "Access-Control-Allow-Origin": "https://zohodeskclabots.netlify.app",
        "Access-Control-Allow-Credentials": "true"
      }
    };
  }
};