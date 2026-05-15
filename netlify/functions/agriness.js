// Netlify Serverless Function — Proxy para Agriness S4 API
// Protege credenciales y evita CORS

const https = require('https');

const AGRINESS_HOST = 'am.agriness.com';
const AGRINESS_PORT = 8243;

// Credenciales desde variables de entorno de Netlify
const WSO2_API_KEY = process.env.WSO2_API_KEY || '';
const S4_USERNAME = process.env.S4_USERNAME || '';
const S4_PASSWORD = process.env.S4_PASSWORD || '';

// Cache del token de autenticacion S4
let s4Token = null;
let s4TokenExpiry = 0;

function makeRequest(method, path, body, headers) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: AGRINESS_HOST,
      port: AGRINESS_PORT,
      path: path,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
      rejectUnauthorized: false,
    };

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
async function getS4Token() {
  if (s4Token && Date.now() < s4TokenExpiry) return s4Token;

  const res = await makeRequest('POST', '/sitio1-swine-default/api/v1/login', {
    username: S4_USERNAME,
    password: S4_PASSWORD,
  }, {
    apikey: WSO2_API_KEY,
  });

  if (res.status === 200 && res.data.access_token) {
    s4Token = res.data.access_token;
    // Expirar 5 min antes para seguridad
    s4TokenExpiry = Date.now() + ((res.data.expires_in || 3600) - 300) * 1000;
    return s4Token;
  }

  throw new Error(`Auth failed: ${res.status} - ${JSON.stringify(res.data)}`);
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
    if (!WSO2_API_KEY || !S4_USERNAME || !S4_PASSWORD) {
      return {
        statusCode: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Credenciales API no configuradas en Netlify' }),
      };
    }

    // Parsear la accion del request
    const body = event.body ? JSON.parse(event.body) : {};
    const { action, params } = body;

    // Obtener token S4
    const token = await getS4Token();

    const authHeaders = {
      apikey: WSO2_API_KEY,
      Authorization: `Bearer ${token}`,
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
        // Health check - intenta autenticar y listar granjas
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
