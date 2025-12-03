const fetch = require('node-fetch');

const {
  ZOHO_CLIENT_ID,
  ZOHO_CLIENT_SECRET,
  ZOHO_REFRESH_TOKEN,
  ZOHO_ORG_ID,
  ZOHO_DC
} = process.env;

const ACCOUNTS_BASE = `https://accounts.zoho.${ZOHO_DC}`;
const DESK_BASE = `https://desk.zoho.${ZOHO_DC}/api/v1`;

let cachedAccessToken = null;
let accessTokenExpiry = 0;

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
    console.error("Erreur OAuth (history):", data);
    throw new Error("Erreur OAuth Zoho");
  }

  cachedAccessToken = data.access_token;
  accessTokenExpiry = now + (data.expires_in || 3600) * 1000;
  return cachedAccessToken;
}

exports.handler = async (event) => {
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

    // Get ticket history (actions + sous-onglets)
    // GET /api/v1/tickets/{ticket_Id}/History
    const url = `${DESK_BASE}/tickets/${ticketId}/History?from=0&limit=50`;

    const res = await fetch(url, {
      headers: {
        Authorization: `Zoho-oauthtoken ${token}`,
        orgId: ZOHO_ORG_ID
      }
    });

    const data = await res.json();
    if (!res.ok) {
      console.error("Erreur Zoho Desk (history):", data);
      return {
        statusCode: 500,
        body: JSON.stringify({ error: "Erreur Zoho Desk", details: data }),
        headers: { "Access-Control-Allow-Origin": "*" }
      };
    }

    // data.data contient normalement la liste des évènements
    const history = Array.isArray(data.data) ? data.data : data;

    return {
      statusCode: 200,
      body: JSON.stringify(history),
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
