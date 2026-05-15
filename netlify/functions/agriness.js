// Netlify Serverless Function — Proxy para Agriness S4 API
// Protege credenciales y evita CORS
// Auth: OAuth2 Client Credentials → WSO2 Gateway (sin S4 login separado)

const https = require('https');

const AGRINESS_HOST = 'am.agriness.com';
const API_PORT = 8243;    // WSO2 API Gateway
const TOKEN_PORT = 9443;  // WSO2 OAuth2 Token Endpoint

// Credenciales desde variables de entorno de Netlify
const WSO2_CONSUMER_KEY = process.env.WSO2_CONSUMER_KEY || '';
const WSO2_CONSUMER_SECRET = process.env.WSO2_CONSUMER_SECRET || '';
const S4_USERNAME = process.env.S4_USERNAME || '';
const S4_PASSWORD = process.env.S4_PASSWORD || '';

// Cache del token OAuth2
let accessToken = null;
let tokenExpiry = 0;

function makeRequest(method, path, body, headers, port) {
  port = port || API_PORT;
  return new Promise((resolve, reject) => {
    const options = {
      hostname: AGRINESS_HOST,
      port: port,
      path: path,
      method: method,
      headers: {
        ...headers,
      },
      rejectUnauthorized: false, // Agriness usa cert auto-firmado
    };

    // Set Content-Type if not already set
    if (!options.headers['Content-Type']) {
      options.headers['Content-Type'] = 'application/json';
    }

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Timeout')); });

    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

// Obtener token OAuth2 del gateway WSO2
// Intenta password grant primero (incluye contexto de usuario S4),
// si falla usa client_credentials grant
async function getAccessToken() {
  if (accessToken && Date.now() < tokenExpiry) return accessToken;

  const credentials = Buffer.from(`${WSO2_CONSUMER_KEY}:${WSO2_CONSUMER_SECRET}`).toString('base64');

  // Intentar password grant (combina gateway auth + user context)
  try {
    const pwBody = `grant_type=password&username=${encodeURIComponent(S4_USERNAME)}&password=${encodeURIComponent(S4_PASSWORD)}`;
    const res = await makeRequest(
      'POST',
      '/oauth2/token',
      pwBody,
      {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      TOKEN_PORT
    );

    if (res.status === 200 && res.data.access_token) {
      accessToken = res.data.access_token;
      tokenExpiry = Date.now() + ((res.data.expires_in || 3600) - 300) * 1000;
      console.log('OAuth2 password grant token obtained, expires in', res.data.expires_in, 's');
      return accessToken;
    }
    console.log('Password grant failed:', res.status, JSON.stringify(res.data));
  } catch (e) {
    console.log('Password grant error:', e.message);
  }

  // Fallback: client_credentials grant
  const res = await makeRequest(
    'POST',
    '/oauth2/token',
    'grant_type=client_credentials',
    {
      'Authorization': `Basic ${credentials}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    TOKEN_PORT
  );

  if (res.status === 200 && res.data.access_token) {
    accessToken = res.data.access_token;
    tokenExpiry = Date.now() + ((res.data.expires_in || 3600) - 300) * 1000;
    console.log('OAuth2 client_credentials token obtained, expires in', res.data.expires_in, 's');
    return accessToken;
  }

  throw new Error(`OAuth2 failed: ${res.status} - ${JSON.stringify(res.data)}`);
}

exports.handler = async (event) => {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: corsHeaders, body: '' };
  }

  try {
    // Verificar que las credenciales esten configuradas
    if (!WSO2_CONSUMER_KEY || !WSO2_CONSUMER_SECRET) {
      return {
        statusCode: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Credenciales API no configuradas en Netlify' }),
      };
    }

    // Parsear la accion del request
    const body = event.body ? JSON.parse(event.body) : {};
    const { action, params } = body;

    // Obtener token OAuth2
    const token = await getAccessToken();

    const authHeaders = {
      'Authorization': `Bearer ${token}`,
    };

    let result;

    switch (action) {
      case 'farms': {
        result = await makeRequest('GET', '/sitio1-swine-default/api/v1/farms', null, authHeaders);
        break;
      }

      case 'kpis_sitio1': {
        const path = '/sitio1-swine-default/v1/swine/reproductive/kpis';
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'kpis_sitio2': {
        const path = '/swinekpisdefault/v1/nursery/kpis';
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'kpis_sitio3': {
        const path = '/swinekpisdefault/v1/finishing/kpis';
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'kpis_weantofinish': {
        const path = '/swinekpisdefault/v1/weantofinish/kpis';
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'servicios': {
        const gender = params.gender || 'female';
        const path = `/sitio1-swine-default/v1/swine/reproductive/mating-list/${gender}`;
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'partos': {
        const gender = params.gender || 'female';
        const path = `/sitio1-swine-default/v1/swine/reproductive/farrowing-list/${gender}`;
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'destetes': {
        const gender = params.gender || 'female';
        const path = `/sitio1-swine-default/v1/swine/reproductive/weaning-list/${gender}`;
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'movimientos': {
        const gender = params.gender || 'female';
        const path = `/sitio1-swine-default/v1/swine/reproductive/fostering-piglet-list/${gender}`;
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'muertes_lechones': {
        const gender = params.gender || 'female';
        const path = `/sitio1-swine-default/v1/swine/reproductive/piglet-death-list/${gender}`;
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'salidas_lotes': {
        const path = '/events-farm-sitio2-3-default/v1/swine/farm/animal-group/output';
        result = await makeRequest('POST', path, params, authHeaders);
        break;
      }

      case 'health': {
        const farms = await makeRequest('GET', '/sitio1-swine-default/api/v1/farms', null, authHeaders);
        result = { status: 200, data: { ok: true, farms: farms.data } };
        break;
      }

      default:
        return {
          statusCode: 400,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: `Accion desconocida: ${action}` }),
        };
    }

    return {
      statusCode: result.status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify(result.data),
    };

  } catch (err) {
    console.error('Proxy error:', err);
    return {
      statusCode: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }),
    };
  }
};
