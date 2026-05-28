// Netlify Serverless Function — Proxy para Agriness S4 API
// Protege credenciales y evita CORS
// Auth: OAuth2 Client Credentials + API Key → WSO2 Gateway + S4 Login → header "token" / "HTTP-AUTHORIZATION"

const https = require('https');

const AGRINESS_HOST = 'am.agriness.com';
const API_PORT = 8243;   // WSO2 API Gateway
const TOKEN_PORT = 9443; // WSO2 OAuth2 Token Endpoint

// Credenciales desde variables de entorno de Netlify
const WSO2_CONSUMER_KEY = process.env.WSO2_CONSUMER_KEY || '';
const WSO2_CONSUMER_SECRET = process.env.WSO2_CONSUMER_SECRET || '';
const S4_USERNAME = process.env.S4_USERNAME || '';
const S4_PASSWORD = process.env.S4_PASSWORD || '';
const WSO2_API_KEY = process.env.WSO2_API_KEY || '';

// Cache de tokens
let wso2Token = null;
let wso2TokenExpiry = 0;
let s4Token = null;
let s4TokenExpiry = 0;
let kpiToken = null;
let kpiTokenExpiry = 0;

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

// Login S4 (sitio1): devuelve { data: { token: "..." } }
// Ese token se pasa como header "token" en llamadas sitio1
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

// Login KPI API: usa apikey para gateway, devuelve access_token para HTTP-AUTHORIZATION
async function getKpiToken() {
  if (kpiToken && Date.now() < kpiTokenExpiry) return kpiToken;

  console.log('Attempting KPI login via /swinekpisdefault/api/v1/login');

  const headers = { 'Content-Type': 'application/json' };
  // Usar API Key para gateway auth en KPI API
  if (WSO2_API_KEY) {
    headers['apikey'] = WSO2_API_KEY;
  } else {
    // Fallback a Bearer token si no hay API Key
    const gatewayToken = await getWso2Token();
    headers['Authorization'] = 'Bearer ' + gatewayToken;
  }

  const res = await makeRequest('POST', '/swinekpisdefault/api/v1/login', {
    username: S4_USERNAME,
    password: S4_PASSWORD,
  }, headers);

  console.log('KPI login response:', res.status, JSON.stringify(res.data).substring(0, 300));

  if (res.status === 200) {
    const token = res.data.access_token || (res.data.data && res.data.data.token) || res.data.token;
    if (token) {
      kpiToken = token;
      // access_token expires in ~518400s (6 days), refresh before that
      const expiresIn = res.data.expires_in || 518400;
      kpiTokenExpiry = Date.now() + (expiresIn - 600) * 1000;
      console.log('KPI token obtained, expires in', expiresIn, 's, length:', token.length);
      return kpiToken;
    }
    console.error('KPI login 200 but no token:', JSON.stringify(res.data));
  }

  throw new Error('KPI login failed: ' + res.status + ' - ' + JSON.stringify(res.data).substring(0, 500));
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

    // Auth para sitio1 (farms, servicios, partos, destetes, etc.)
    const gatewayToken = await getWso2Token();
    let s4AccessToken = null;
    try { s4AccessToken = await getS4Token(); } catch (err) { console.error('S4 auth failed:', err.message); }

    const authHeaders = { 'Authorization': 'Bearer ' + gatewayToken };
    if (s4AccessToken) { authHeaders['token'] = s4AccessToken; }

    // Auth para KPI API (usa apikey + HTTP-AUTHORIZATION)
    let kpiHeaders = null;
    const isKpiAction = action && action.startsWith('kpis_');
    if (isKpiAction) {
      try {
        const kpiAccessToken = await getKpiToken();
        kpiHeaders = { 'Content-Type': 'application/json' };
        if (WSO2_API_KEY) {
          kpiHeaders['apikey'] = WSO2_API_KEY;
        } else {
          kpiHeaders['Authorization'] = 'Bearer ' + gatewayToken;
        }
        kpiHeaders['HTTP-AUTHORIZATION'] = kpiAccessToken;
        console.log('KPI headers ready, HTTP-AUTHORIZATION length:', kpiAccessToken.length);
      } catch (err) {
        console.error('KPI auth failed:', err.message);
        // Fallback: try with standard auth
        kpiHeaders = { ...authHeaders };
      }
    }

    let result;

    switch (action) {
      case 'health':
      case 'farms':
        result = await makeRequest('GET', '/sitio1-swine-default/api/v1/farms', null, authHeaders);
        break;
      case 'kpis_sitio1':
        result = await makeRequest('POST', '/swinekpisdefault/v1/swine/reproductive/kpis', params, kpiHeaders || authHeaders);
        break;
      case 'kpis_sitio2':
        result = await makeRequest('POST', '/swinekpisdefault/v1/swine/nursery/kpis', params, kpiHeaders || authHeaders);
        break;
      case 'kpis_sitio3':
        result = await makeRequest('POST', '/swinekpisdefault/v1/swine/finishing/kpis', params, kpiHeaders || authHeaders);
        break;
      case 'kpis_weantofinish':
        result = await makeRequest('POST', '/swinekpisdefault/v1/swine/weantofinish/kpis', params, kpiHeaders || authHeaders);
        break;
      case 'servicios': {
        const g1 = (params && params.gender) || 'female';
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/mating-list/' + g1, params, authHeaders);
        break;
      }
      case 'partos':
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/farrowing-list/' + ((params && params.gender) || 'female'), params, authHeaders);
        break;
      case 'destetes':
        result = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/weaning-list/' + ((params && params.gender) || 'female'), params, authHeaders);
        break;
      case 'eventos':
        result = await makeRequest('POST', '/events-farm-sitio2-3-default/v1/events', params, authHeaders);
        break;
      case 'raw': {
        // Exploratory: hit arbitrary sitio1 path
        const rawPath = (params && params.path) || '';
        const rawMethod = (params && params.method) || 'POST';
        const rawBody = (params && params.body) || {};
        result = await makeRequest(rawMethod, rawPath, rawBody, authHeaders);
        break;
      }
      default:
        return { statusCode: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          body: JSON.stringify({ error: 'Accion no reconocida: ' + action }) };
    }

    console.log('API response for', action, ':', result.status, JSON.stringify(result.data).substring(0, 200));

    // Retry con token refresh si 401 o 403 en KPI endpoints
    if ((result.status === 403 || result.status === 401) && isKpiAction) {
      console.log(result.status, 'on KPI endpoint, clearing cached tokens and retrying...');
      kpiToken = null;
      kpiTokenExpiry = 0;
      wso2Token = null;
      wso2TokenExpiry = 0;
      try {
        const freshKpiToken = await getKpiToken();
        const freshKpiHeaders = { 'Content-Type': 'application/json' };
        if (WSO2_API_KEY) {
          freshKpiHeaders['apikey'] = WSO2_API_KEY;
        } else {
          const freshGw = await getWso2Token();
          freshKpiHeaders['Authorization'] = 'Bearer ' + freshGw;
        }
        freshKpiHeaders['HTTP-AUTHORIZATION'] = freshKpiToken;
        console.log('Retrying', action, 'with fresh KPI token, length:', freshKpiToken.length);

        const kpiPaths = {
          'kpis_sitio1': '/swinekpisdefault/v1/swine/reproductive/kpis',
          'kpis_sitio2': '/swinekpisdefault/v1/swine/nursery/kpis',
          'kpis_sitio3': '/swinekpisdefault/v1/swine/finishing/kpis',
          'kpis_weantofinish': '/swinekpisdefault/v1/swine/weantofinish/kpis',
        };
        const retryResult = await makeRequest('POST', kpiPaths[action], params, freshKpiHeaders);
        console.log('Retry response for', action, ':', retryResult.status, JSON.stringify(retryResult.data).substring(0, 200));
        if (retryResult.status !== 403 && retryResult.status !== 401) {
          return {
            statusCode: retryResult.status,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify(retryResult.data),
          };
        }
      } catch (retryErr) {
        console.error('KPI retry failed:', retryErr.message);
      }
    }

    // Retry con token refresh si 401 en cualquier endpoint (token WSO2 expirado/invalidado)
    if (result.status === 401 && !isKpiAction) {
      console.log('401 on', action, '- clearing ALL cached tokens and retrying...');
      wso2Token = null;
      wso2TokenExpiry = 0;
      s4Token = null;
      s4TokenExpiry = 0;
      try {
        const freshGw = await getWso2Token();
        let freshS4 = null;
        try { freshS4 = await getS4Token(); } catch (err) { console.error('S4 re-auth failed:', err.message); }
        const freshHeaders = { 'Authorization': 'Bearer ' + freshGw };
        if (freshS4) freshHeaders['token'] = freshS4;
        console.log('Retrying', action, 'with fresh WSO2+S4 tokens');

        // Rebuild the request for the current action
        let retryResult;
        switch (action) {
          case 'health':
          case 'farms':
            retryResult = await makeRequest('GET', '/sitio1-swine-default/api/v1/farms', null, freshHeaders);
            break;
          case 'servicios':
            retryResult = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/mating-list/' + ((params && params.gender) || 'female'), params, freshHeaders);
            break;
          case 'partos':
            retryResult = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/farrowing-list/' + ((params && params.gender) || 'female'), params, freshHeaders);
            break;
          case 'destetes':
            retryResult = await makeRequest('POST', '/sitio1-swine-default/v1/swine/reproductive/weaning-list/' + ((params && params.gender) || 'female'), params, freshHeaders);
            break;
          case 'eventos':
            retryResult = await makeRequest('POST', '/events-farm-sitio2-3-default/v1/events', params, freshHeaders);
            break;
          default:
            retryResult = null;
        }
        if (retryResult && retryResult.status !== 401) {
          console.log('401 retry succeeded for', action, ':', retryResult.status);
          return {
            statusCode: retryResult.status,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify(retryResult.data),
          };
        }
      } catch (retryErr) {
        console.error('401 retry failed:', retryErr.message);
      }
    }

    // Retry con token refresh si 403 en Sitio1 event endpoints (servicios, partos, destetes)
    const isSitio1Event = ['servicios', 'partos', 'destetes'].includes(action);
    if (result.status === 403 && isSitio1Event) {
      console.log('403 on sitio1 event endpoint (' + action + '), clearing S4 token and retrying...');
      s4Token = null;
      s4TokenExpiry = 0;
      wso2Token = null;
      wso2TokenExpiry = 0;
      try {
        const freshGw = await getWso2Token();
        const freshS4 = await getS4Token();
        const freshHeaders = { 'Authorization': 'Bearer ' + freshGw };
        if (freshS4) freshHeaders['token'] = freshS4;
        console.log('Retrying', action, 'with fresh S4 token, length:', freshS4 ? freshS4.length : 0);

        const sitio1Paths = {
          'servicios': '/sitio1-swine-default/v1/swine/reproductive/mating-list/' + ((params && params.gender) || 'female'),
          'partos': '/sitio1-swine-default/v1/swine/reproductive/farrowing-list/' + ((params && params.gender) || 'female'),
          'destetes': '/sitio1-swine-default/v1/swine/reproductive/weaning-list/' + ((params && params.gender) || 'female'),
        };
        const retryResult = await makeRequest('POST', sitio1Paths[action], params, freshHeaders);
        console.log('Retry response for', action, ':', retryResult.status, JSON.stringify(retryResult.data).substring(0, 200));
        if (retryResult.status !== 403) {
          return {
            statusCode: retryResult.status,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            body: JSON.stringify(retryResult.data),
          };
        }
      } catch (retryErr) {
        console.error('Sitio1 retry failed:', retryErr.message);
      }
    }

    return {
      statusCode: result.status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify(result.data),
    };
  } catch (error) {
    console.error('Proxy error:', error.message);
    return {
      statusCode: 502,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ error: 'Error de proxy: ' + error.message }),
    };
  }
};
