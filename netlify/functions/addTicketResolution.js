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
    headers: {
      "Access-Control-Allow-Origin": "https://zohodeskclabots.netlify.app",
      "Access-Control-Allow-Credentials": "true"
    }
  };
}

async function parseZohoResponse(res, context) {
  const responseText = await res.text();
  if (!responseText) {
    console.warn(`Réponse vide de l'API Zoho Desk${context ? ` (${context})` : ''}`);
    return { data: null, raw: '' };
  }

  try {
    return { data: JSON.parse(responseText), raw: responseText };
  } catch (parseError) {
    console.error(`Erreur de parsing JSON${context ? ` (${context})` : ''}:`, parseError, "Réponse brute:", responseText);
    throw new Error(`Réponse invalide de l'API Zoho Desk${context ? ` (${context})` : ''}`);
  }
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
    console.error("Erreur OAuth (addTicketResolution):", data);
    throw new Error("Erreur OAuth Zoho");
  }

  cachedAccessToken = data.access_token;
  accessTokenExpiry = now + (data.expires_in || 3600) * 1000;
  return cachedAccessToken;
}

exports.handler = async (event) => {
  console.log('addTicketResolution - Headers reçus:', JSON.stringify(event.headers));
  console.log('addTicketResolution - Cookies:', event.headers?.cookie || 'Aucun cookie');

  if (!verifyAuth(event)) {
    console.log('addTicketResolution - Échec de l\'authentification');
    return unauthorized();
  }

  console.log('addTicketResolution - Authentification réussie');

  // Vérifier que c'est une requête POST
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Méthode non autorisée. Utilisez POST.' }),
      headers: { "Access-Control-Allow-Origin": "*" }
    };
  }

  try {
    // Parser le corps de la requête
    let body;
    try {
      body = JSON.parse(event.body);
    } catch (e) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Corps de requête invalide. JSON attendu.' }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    const ticketId = body.ticketId;
    const resolutionContent = body.resolutionContent;

    if (!ticketId || !resolutionContent) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: "Paramètres manquants: ticketId et resolutionContent sont requis" }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    const token = await getAccessToken();

    // Récupérer les détails du ticket pour obtenir la résolution actuelle
    const ticketUrl = `${DESK_BASE}/tickets/${ticketId}`;
    const ticketRes = await fetch(ticketUrl, {
      headers: {
        Authorization: `Zoho-oauthtoken ${token}`,
        orgId: ZOHO_ORG_ID
      }
    });

    if (!ticketRes.ok) {
      const errorData = await ticketRes.json();
      console.error("Erreur lors de la récupération du ticket:", errorData);
      throw new Error("Impossible de récupérer les détails du ticket");
    }

    const ticketData = await ticketRes.json();
    // La résolution renvoyée par l'API peut être une chaîne ou un objet { content }
    const currentResolution = typeof ticketData.resolution === 'string'
      ? ticketData.resolution
      : (ticketData.resolution && ticketData.resolution.content) || '';

    // Construire la nouvelle résolution en ajoutant le nouveau feedback
    const timestamp = new Date().toISOString();
    const newResolution = currentResolution
      ? `${currentResolution}\n\n[Feedback client - ${timestamp}]\n${resolutionContent}`
      : `[Feedback client - ${timestamp}]\n${resolutionContent}`;

    const resolutionEndpoint = `${DESK_BASE}/tickets/${ticketId}/resolution`;
    const ticketUpdateEndpoint = `${DESK_BASE}/tickets/${ticketId}`;

    async function sendResolutionUpdate(oauthToken, contextSuffix = '') {
      // On tente plusieurs formes de payload pour s'adapter aux variations de l'API Desk
      const attempts = [
        {
          source: 'resolution-endpoint',
          url: resolutionEndpoint,
          body: { content: newResolution },
          fallbackStatuses: [400, 404, 405, 415]
        },
        {
          source: 'ticket-fallback-object',
          url: ticketUpdateEndpoint,
          body: { resolution: { content: newResolution } },
          fallbackStatuses: [400, 415]
        },
        {
          source: 'ticket-fallback-string',
          url: ticketUpdateEndpoint,
          body: { resolution: newResolution },
          fallbackStatuses: []
        }
      ];

      let lastRes = null;
      let lastParsed = null;
      let lastSource = null;

      for (const attempt of attempts) {
        const res = await fetch(attempt.url, {
          method: 'PUT',
          headers: {
            Authorization: `Zoho-oauthtoken ${oauthToken}`,
            orgId: ZOHO_ORG_ID,
            Accept: 'application/json',
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(attempt.body)
        });

        const parsed = await parseZohoResponse(res, `mise à jour de la résolution${contextSuffix ? ` ${contextSuffix}` : ''} (${attempt.source})`);

        if (res.ok) {
          return { res, parsed, source: attempt.source };
        }

        lastRes = res;
        lastParsed = parsed;
        lastSource = attempt.source;

        const canTryNext = attempt.fallbackStatuses.includes(res.status);
        if (!canTryNext) {
          break;
        }

        console.warn(`${attempt.source} (${res.status}) ; tentative avec une autre forme de payload...`);
      }

      return { res: lastRes, parsed: lastParsed, source: lastSource };
    }

    let { res: updateRes, parsed: parsedUpdateData, source: updateSource } = await sendResolutionUpdate(token);
    let responseData = parsedUpdateData.data;

    if (!updateRes.ok && updateRes.status === 401) {
      console.error("Token Zoho expiré, tentative de rafraîchissement...");
      cachedAccessToken = null;
      accessTokenExpiry = 0;
      const newToken = await getAccessToken();

      console.log("Nouveau token obtenu, réessai de la mise à jour...");
      const retryResult = await sendResolutionUpdate(newToken, "(réessai)");
      updateRes = retryResult.res;
      parsedUpdateData = retryResult.parsed;
      updateSource = retryResult.source;
      responseData = parsedUpdateData.data;
    }

    if (!updateRes.ok) {
      const errorMessage = (parsedUpdateData && parsedUpdateData.data && parsedUpdateData.data.message) ||
        (parsedUpdateData && parsedUpdateData.data && parsedUpdateData.data.error) ||
        (parsedUpdateData && parsedUpdateData.raw) ||
        "Erreur inconnue de l'API Zoho Desk";
      console.error("Erreur lors de la mise à jour de la résolution:", {
        status: updateRes.status,
        source: updateSource,
        response: parsedUpdateData && (parsedUpdateData.data || parsedUpdateData.raw)
      });
      throw new Error(`Impossible de mettre à jour la résolution du ticket: ${errorMessage} (code: ${updateRes.status})`);
    }

    responseData = responseData || { success: true, message: "Mise à jour réussie (réponse vide)" };
    if (updateSource === 'ticket-fallback') {
      console.log("Mise à jour effectuée via PUT /tickets/{id} (fallback résolution)");
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        success: true,
        message: 'Feedback ajouté avec succès comme nouvelle résolution',
        ticketId: ticketId,
        newResolution: newResolution,
        response: responseData
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
