// Netlify Serverless Function — Proxy para Agriness S4 API
// Protege credenciales y evita CORS
// Auth: OAuth2 Client Credentials → WSO2 Gateway + S4 Login → header "token"

const https = require('https');

const AGRINESS_HOST = 'am.agriness.com';
const API_PORT = 8243;    // WSO2 API Gateway
const TOKEN_PORT = 9443;  // WSO2 OAuth2 Token Endpoint

// Credenciales desde variables de entorno de Netlify
const WSO2_CONSUMER_KEY = process.env.WSO2_CONSUMER_KEY || '';
const WSO2_CONSUMER_SECRET = process.env.WSO2_CONSUMER_SECRET || '';
const S4_USERNAME = process.env.S4_USERNAME || '';
const S4_PASSWORD = process.env.S4_PASSWORD || '';

// Cache de tokens
let wso2Token = null;
let wso2TokenExpiry = 0;
let s4Token = null;
let s4TokenExpiry = 0;

function makeRequest(method, path, body, headers, port) {
  port = port || API_PORT;
  return new Promise((resolve, reject) => {
    const options = {
      hostname: AGRINESS_HOST,
      port: port,
      path: path,
      method: method,
      headers: { ...headers },
      rejectUnauthorized: false,
    };

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

async function getWso2Token() {
  if (wso2Token && Date.now() < wso2TokenExpiry) return wso2Token;

  const credentials = Buffer.from(WSO2_CONSUMER_KEY + ':' + WSO2_CONSUMER_SECRET).toString('base64');

  const res = await makeRequest(
    'POST', '/oauth2/token', 'grant_type=client_credentials',
    { 'Authorization': 'Basic ' + credentials, 'Content-Type': 'application/x-www-form-urlencoded' },
    TOKEN_PORT
  );

  if (res.status === 200 && res.data.access_token) {
    wso2Token = res.data.access_token;
    wso2TokenExpiry = Date.now() + ((res.data.expires_in || 3600) - 300) * 1000;
    console.log('WSO2 OAuth2 token obtained, expires in', res.data.expires_in, 's');
    return wso2Token;
  }

  throw new Error('WSO2 OAuth2 failed: ' + res.status + ' - ' + JSON.stringify(res.data));
}

// Login S4: devuelve { data: { token: "..." } }
// Ese token se pasa como header "token" en llamadas API
async function getS4Token() {
  if (s4Token && Date.now() < s4TokenExpiry) return s4Token;

  const gatewayToken = await getWso2Token();
  console.log('Attempting S4 login with username:', S4_USERNAME);

  const res = await makeRequest('POST', '/sitio1-swine-default/api/v1/login', {
    username: S4_USERNAME,
    password: S4_PASSWORD,
  }, {
    'Authorization': 'Bearer ' + gatewayToken,
  });

  console.log('S4 login response:', res.status, JSON.stringify(res.data).substring(0, 500));

  if (res.status === 200) {
    const token = (res.data && res.data.data && res.data.data.token) || (res.data && res.data.token) || (res.data && res.data.access_token);
    if (token) {
      s4Token = token;
      s4TokenExpiry = Date.now() + 23 * 60 * 60 * 1000;
      console.log('S4 token obtained, length:', token.length);
      return s4Token;
    }
    console.error('S4 login 200 but no token:', JSON.stringify(res.data));
  }

  // Fallback: WSO2 password grant
  console.log('S4 login failed (' + res.status + '), trying password grant...');
  const credentials = Buffer.from(WSO2_CONSUMER_KEY + ':' + WSO2_CONSUMER_SECRET).toString('base64');
  const pwRes = await makeRequest(
    'POST', '/oauth2/token',
    'grant_type=password&username=' + encodeURIComponent(S4_USERNAME) + '&password=' + encodeURIComponent(S4_PASSWORD),
    { 'Authorization': 'Basic ' + credentials, 'Content-Type': 'application/x-www-form-urlencoded' },
    TOKEN_PORT
  );

  console.log('Password grant response:', pwRes.status);

  if (pwRes.status === 200 && pwRes.data.access_token) {
    s4Token = pwRes.data.access_token;
    s4TokenExpiry = Date.now() + ((pwRes.data.expires_in || 3600) - 300) * 1000;
    console.log('Using password grant token as S4 fallback');
    return s4Token;
  }

  throw new Error('S4 auth failed. Login: ' + res.status + '. PwGrant: ' + pwRes.status);
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
    if (!WSO2_CONSUMER_KEY || !WSO2_CONSUMER_SECRET || !S4_USERNAME || !S4_PASSWORD) {
      return { statusCode: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Credenciales API no configuradas en Netlify' }) };
    }

    const body = event.body ? JSON.parse(event.body) : {};
    const { action, params } = body;

    const gatewayToken = await getWso2Token();
    let s4AccessToken = null;
    try { s4AccessToken = await getS4Token(); } catch (err) { console.error('S4 auth failed:', err.message); }

    // AUTH: Authorization Bearer para gateway, header "token" para backend S4
    const authHeaders = { 'Authorization': 'Bearer ' + gatewayToken };
    if (s4AccessToken) { authHeaders['token'] = s4AccessToken; }

    let result;

    switch (action) {
      case 'farms':
        result = await makeRequest('GET', '/sitio1-swine-default/api/v1/farms', null, authHeaders);
        break;
      case 'kpis_sitio1':
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/kpis', params, authHeaders);
        break;
      case 'kpis_sitio2':
        result = await makeRequest('POST', '/swinekpisdefault/v1/nursery/kpis', params, authHeaders);
        break;
      case 'kpis_sitio3':
        result = await makeRequest('POST', '/swinekpisdefault/v1/finishing/kpis', params, authHeaders);
        break;
      case 'kpis_weantofinish':
        result = await makeRequest('POST', '/swinekpisdefault/v1/weantofinish/kpis', params, authHeaders);
        break;
      case 'servicios': {
        const g1 = (params && params.gender) || 'female';
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/mating-list/' + g1, params, authHeaders);
        break;
      }
      case 'partos': {
        const g2 = (params && params.gender) || 'female';
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/farrowing-list/' + g2, params, authHeaders);
        break;
      }
      case 'destetes': {
        const g3 = (params && params.gender) || 'female';
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/weaning-list/' + g3, params, authHeaders);
        break;
      }
      case 'movimientos': {
        const g4 = (params && params.gender) || 'female';
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/fostering-piglet-list/' + g4, params, authHeaders);
        break;
      }
      case 'muertes_lechones': {
        const g5 = (params && params.gender) || 'female';
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/piglet-death-list/' + g5, params, authHeaders);
        break;
      }
      case 'salidas_lotes':
        result = await makeRequest('POST', '/events-farm-sitio2-3-default/v1/swine/farm/animal-group/output', params, authHeaders);
        break;
      case 'health': {
        const loginRes = await makeRequest('POST', '/sitio1-swine-default/api/v1/login', {
          username: S4_USERNAME, password: S4_PASSWORD,
        }, { 'Authorization': 'Bearer ' + gatewayToken });
        const farmsRes = await makeRequest('GET', '/sitio1-swine-default/api/v1/farms', null, authHeaders);
        result = { status: 200, data: {
          ok: true,
          wso2_token: gatewayToken ? 'ok' : 'MISSING',
          s4_token: s4AccessToken ? 'ok' : 'MISSING',
          login_test: { status: loginRes.status, body: loginRes.data },
          farms_test: { status: farmsRes.status, body: farmsRes.data },
        }};
        break;
      }
      default:
        return { statusCode: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Accion desconocida: ' + action }) };
    }

    return { statusCode: result.status, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify(result.data) };

  } catch (err) {
    console.error('Proxy error:', err);
    return { statusCode: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: err.message }) };
  }
};
