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

// ---- Compras: baja el CSV de facturas de compra desde Google Drive (Smart ARCA / Pymetech) ----
// Archivo publico (anyone-with-link), se reemplaza a diario 07:30 ARG. Devolvemos el texto crudo.
const COMPRAS_CSV_ID = process.env.COMPRAS_CSV_ID || '1zEc1FIltSoRfW8lBhnlX_TsiZMbjtCni';
function fetchExternal(url, redirects) {
  redirects = redirects || 0;
  return new Promise((resolve, reject) => {
    if (redirects > 6) return reject(new Error('Too many redirects'));
    const req = https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (JofaDashboard)' } }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        const next = res.headers.location.startsWith('http') ? res.headers.location : new URL(res.headers.location, url).href;
        return resolve(fetchExternal(next, redirects + 1));
      }
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode, data: data }));
    });
    req.on('error', reject);
    req.setTimeout(25000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

// Store de Netlify Blobs para el mapeo de categorias de compras (compartido).
// Netlify no siempre auto-configura Blobs en funciones clasicas: si estan seteadas
// NETLIFY_SITE_ID y NETLIFY_BLOBS_TOKEN las usamos; si no, intento auto.
function getCatStore() {
  const { getStore } = require('@netlify/blobs');
  const siteID = process.env.NETLIFY_SITE_ID || process.env.SITE_ID;
  const token = process.env.NETLIFY_BLOBS_TOKEN || process.env.NETLIFY_API_TOKEN;
  if (siteID && token) return getStore({ name: 'jofa-compras', consistency: 'strong', siteID: siteID, token: token });
  return getStore({ name: 'jofa-compras', consistency: 'strong' });
}

// ---- Afip SDK: wslpg (Liquidaciones Primarias de Granos). JOFA como COMPRADOR (representada); cert de Pulporte. ----
// IMPORTANTE: el cert/key/token NO van en env vars (AWS Lambda limita el total de env vars a 4KB y el PEM lo excede).
// Se guardan en Netlify Blobs (clave 'afip_secrets') y se leen en runtime. Solo datos chicos quedan en env.
const AFIP_CERT_CUIT = process.env.AFIP_CERT_CUIT || '';              // CUIT del certificado (Pulporte) = tax_id en /auth
const AFIP_JOFA_CUIT = process.env.AFIP_JOFA_CUIT || '30710762372';  // representada (JOFA) = auth.cuit
const AFIP_WSLPG_PTOEMIS = (process.env.AFIP_WSLPG_PTOEMIS || '0')
  .split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n >= 0);
// Nombres aprox de granos (se puede refinar con tipoGranoConsultar). Fallback: "Grano <cod>".
const GRANOS_NOMBRE = { 2: 'Maíz', 3: 'Soja', 14: 'Trigo', 23: 'Girasol', 29: 'Sorgo', 31: 'Cebada', 34: 'Poroto' };

// PEM: normaliza saltos de linea (\n literal o CRLF) para que el cert/key sean PEM validos.
function pemFix(s) {
  if (!s) return '';
  let v = String(s).trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
  v = v.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return v.trim() + '\n';
}

let wslpgTA = null;          // { token, sign, exp }
let afipSecretsCache = null; // { cert, key, token, exp }

// Lee cert/key/token de Blobs (preferido) con fallback a env vars (por si alguien las deja chicas en dev).
async function getAfipSecrets() {
  if (afipSecretsCache && Date.now() < afipSecretsCache.exp) return afipSecretsCache;
  let b = {};
  try { b = (await getCatStore().get('afip_secrets', { type: 'json' })) || {}; } catch (e) { b = {}; }
  afipSecretsCache = {
    cert: pemFix(b.cert || process.env.AFIP_CERT || ''),
    key: pemFix(b.key || process.env.AFIP_KEY || ''),
    token: String(b.token || process.env.AFIPSDK_TOKEN || '').trim(),
    exp: Date.now() + 5 * 60 * 1000,
  };
  return afipSecretsCache;
}

function afipPost(path, bodyObj, bearer) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(bodyObj);
    const options = {
      hostname: 'app.afipsdk.com', port: 443, path: path, method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + (bearer || ''),
        'Content-Length': Buffer.byteLength(payload),
      },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => { try { resolve({ status: res.statusCode, data: JSON.parse(data) }); } catch { resolve({ status: res.statusCode, data: data }); } });
    });
    req.on('error', reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error('Timeout Afip SDK')); });
    req.write(payload); req.end();
  });
}

async function getWslpgTA(force) {
  if (!force && wslpgTA && Date.now() < wslpgTA.exp) return wslpgTA;
  const s = await getAfipSecrets();
  if (!s.token || !s.cert || !s.key) throw new Error('Faltan secretos Afip (cert/key/token) en Blobs; usar accion granos_secrets_set.');
  const r = await afipPost('/api/v1/afip/auth', {
    environment: 'prod', tax_id: String(AFIP_CERT_CUIT), wsid: 'wslpg',
    cert: s.cert, key: s.key, force_create: !!force,
  }, s.token);
  if (r.status === 200 && r.data && r.data.token && r.data.sign) {
    const exp = r.data.expirationTime ? (new Date(r.data.expirationTime).getTime() - 5 * 60 * 1000) : (Date.now() + 11 * 3600 * 1000);
    wslpgTA = { token: r.data.token, sign: r.data.sign, exp: exp };
    return wslpgTA;
  }
  throw new Error('Afip SDK auth wslpg fallo (' + r.status + '): ' + JSON.stringify(r.data).slice(0, 300));
}

async function wslpgRequest(method, extra, cuitRep) {
  const s = await getAfipSecrets();
  const ta = await getWslpgTA(false);
  const cuit = Number(cuitRep || AFIP_JOFA_CUIT);
  const params = Object.assign({ auth: { token: ta.token, sign: ta.sign, cuit: cuit } }, extra || {});
  return afipPost('/api/v1/afip/requests', { environment: 'prod', method: method, wsid: 'wslpg', params: params }, s.token);
}

// Normaliza una liquidacion (liqConsReturn) a una fila de compra de grano.
function normLiqGrano(ret, ptoEmision, nroOrden) {
  const L = (ret && ret.liquidacion) || {};
  const A = (ret && ret.autorizacion) || {};
  const fecha = A.fechaLiquidacion || L.fechaPrecioOperacion || '';
  return {
    origen: 'granos', ptoEmision: ptoEmision, nroOrden: nroOrden,
    fecha: fecha, mes: String(fecha).slice(0, 7),
    cuitVendedor: L.cuitVendedor || null,
    codGrano: L.codGrano != null ? L.codGrano : null,
    grano: GRANOS_NOMBRE[L.codGrano] || ('Grano ' + (L.codGrano != null ? L.codGrano : '?')),
    kg: Number(A.totalPesoNeto || L.pesoNetoSinCertificado || 0),
    neto: Number(A.subTotal || 0),
    iva: Number(A.importeIva || 0),
    total: Number(A.operacionConIva || 0),
    retenciones: Number(A.totalRetencion || 0),
    netoAPagar: Number(A.totalNetoAPagar || 0),
    coe: A.coe || null, estado: A.estado || '', campania: L.campaniaPPal || null,
  };
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

  const J = (s, o) => ({ statusCode: s, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify(o) });

  try {
    if (!WSO2_CONSUMER_KEY || !WSO2_CONSUMER_SECRET || !S4_USERNAME || !S4_PASSWORD) {
      return { statusCode: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        body: JSON.stringify({ error: 'Credenciales API no configuradas en Netlify' }) };
    }

    const body = event.body ? JSON.parse(event.body) : {};
    const { action, params } = body;

    // Compras: baja el CSV de Drive y lo devuelve crudo (no requiere auth de Agriness)
    if (action === 'compras') {
      try {
        let r = await fetchExternal('https://drive.usercontent.google.com/download?id=' + COMPRAS_CSV_ID + '&export=download');
        if (!r.data || r.data.indexOf('fecha') === -1) {
          // fallback al endpoint clasico
          r = await fetchExternal('https://drive.google.com/uc?export=download&id=' + COMPRAS_CSV_ID);
        }
        return {
          statusCode: 200,
          headers: { ...corsHeaders, 'Content-Type': 'text/csv; charset=utf-8', 'Cache-Control': 'public, max-age=1800' },
          body: r.data,
        };
      } catch (e) {
        return { statusCode: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ error: 'No se pudo bajar compras: ' + e.message }) };
      }
    }

    // Mapeo de categorias de compras COMPARTIDO (Netlify Blobs). No requiere auth de Agriness.
    if (action === 'cat_get') {
      try {
        const store = getCatStore();
        const data = await store.get('categorias', { type: 'json' });
        return { statusCode: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify(data || { categorias: null, mapeo: {} }) };
      } catch (e) {
        return { statusCode: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ categorias: null, mapeo: {}, _error: e.message }) };
      }
    }
    if (action === 'cat_set') {
      try {
        const store = getCatStore();
        await store.setJSON('categorias', params || {});
        return { statusCode: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true }) };
      } catch (e) {
        return { statusCode: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: false, error: e.message }) };
      }
    }
    // Config general compartida (ej. piso PORMAG)
    if (action === 'cfg_get') {
      try {
        const store = getCatStore();
        const data = await store.get('config', { type: 'json' });
        return { statusCode: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify(data || {}) };
      } catch (e) {
        return { statusCode: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ _error: e.message }) };
      }
    }
    if (action === 'cfg_set') {
      try {
        const store = getCatStore();
        // Merge: no pisar otras claves del config (ej. guardar sueldos no debe borrar pormag)
        let cur = {};
        try { cur = (await store.get('config', { type: 'json' })) || {}; } catch (e) { cur = {}; }
        const next = Object.assign({}, cur, params || {});
        await store.setJSON('config', next);
        return { statusCode: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true, config: next }) };
      } catch (e) {
        return { statusCode: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: false, error: e.message }) };
      }
    }

    // ---- GRANOS (wslpg): liquidaciones primarias donde JOFA es comprador ----
    // Carga de secretos Afip en Blobs (cert/key/token NO van en env vars por el limite de 4KB de Lambda).
    if (action === 'granos_secrets_set') {
      try {
        const p = params || {};
        if (!p.cert || !p.key) return J(200, { ok: false, error: 'Mandar al menos cert y key (token opcional si queda en env var).' });
        const store = getCatStore();
        let cur = {};
        try { cur = (await store.get('afip_secrets', { type: 'json' })) || {}; } catch (e) { cur = {}; }
        const cert = pemFix(p.cert), key = pemFix(p.key);
        const token = p.token ? String(p.token).trim() : (cur.token || '');
        await store.setJSON('afip_secrets', { cert: cert, key: key, token: token });
        afipSecretsCache = null;
        return J(200, {
          ok: true,
          cert: { largo: cert.length, begin: /^-----BEGIN /.test(cert), end: /-----\n?$/.test(cert) },
          key: { largo: key.length, begin: /^-----BEGIN /.test(key) },
          token: { guardado: !!token, largo: token.length },
        });
      } catch (e) { return J(200, { ok: false, error: e.message }); }
    }

    // Diagnostico de formato de cert/key (sin exponer contenido).
    if (action === 'granos_cert_check') {
      const s = await getAfipSecrets();
      const info = (pem) => ({
        presente: !!pem, largo: pem ? pem.length : 0,
        empiezaBEGIN: /^-----BEGIN /.test(pem || ''),
        terminaEND: /-----\n?$/.test(pem || ''),
        lineas: pem ? pem.split('\n').length : 0,
      });
      return J(200, {
        fuente: 'blobs+env', token: !!s.token, tokenLargo: s.token ? s.token.length : 0,
        certCuit: AFIP_CERT_CUIT || null, jofaCuit: AFIP_JOFA_CUIT, ptoEmis: AFIP_WSLPG_PTOEMIS,
        cert: info(s.cert), key: info(s.key),
        certHeader: (s.cert || '').slice(0, 28), keyHeader: (s.key || '').slice(0, 32),
      });
    }

    // Escaner de puntos de emision: prueba un rango y devuelve el ultimo nroOrden de cada uno.
    if (action === 'granos_scan') {
      const sec = await getAfipSecrets();
      if (!sec.token || !sec.cert || !sec.key || !AFIP_CERT_CUIT) return J(200, { ok: false, error: 'Faltan secretos Afip.' });
      const from = Math.max((params && params.from != null) ? (parseInt(params.from, 10) || 0) : 1, 0);
      let to = (params && params.to != null) ? parseInt(params.to, 10) : (from + 5);
      if (isNaN(to)) to = from + 5;
      if (to < from) to = from;
      if (to - from > 7) to = from + 7; // tope por timeout (~1.5s por punto)
      const cuitRep = (params && params.cuit) ? String(params.cuit) : AFIP_JOFA_CUIT;
      const res = {};
      try {
        for (let pe = from; pe <= to; pe++) {
          const r = await wslpgRequest('liquidacionUltimoNroOrdenConsultar', { ptoEmision: pe }, cuitRep);
          const ret = (r.data && (r.data.liqUltNroOrdenReturn || r.data)) || {};
          const err = ret.errores && ret.errores.error;
          res[pe] = { nroOrden: ret.nroOrden != null ? ret.nroOrden : null, errores: err || null, status: r.status };
        }
        return J(200, { ok: true, representada: cuitRep, desde: from, hasta: to, res: res });
      } catch (e) { return J(200, { ok: false, desde: from, parcial: res, error: e.message }); }
    }

    // Sonda: consulta liquidaciones por (ptoEmision, nroOrden) puntuales para entender la numeracion.
    if (action === 'granos_nro') {
      const sec = await getAfipSecrets();
      if (!sec.token || !sec.cert || !sec.key || !AFIP_CERT_CUIT) return J(200, { ok: false, error: 'Faltan secretos Afip.' });
      const pe = (params && params.pto != null) ? Number(params.pto) : 0;
      const cuitRep = (params && params.cuit) ? String(params.cuit) : AFIP_JOFA_CUIT;
      let nros = (params && Array.isArray(params.nros)) ? params.nros : [(params && params.nro != null) ? params.nro : 0];
      nros = nros.slice(0, 7).map(Number);
      const out = {};
      try {
        for (const n of nros) {
          const r = await wslpgRequest('liquidacionXNroOrdenConsultar', { ptoEmision: pe, nroOrden: n }, cuitRep);
          const lc = (r.data && (r.data.liqConsReturn || r.data)) || {};
          const has = !!(lc.liquidacion || lc.autorizacion);
          out[n] = has
            ? { hay: true, coe: (lc.autorizacion && lc.autorizacion.coe) || null, vendedor: (lc.liquidacion && lc.liquidacion.cuitVendedor) || null, neto: (lc.autorizacion && lc.autorizacion.subTotal) || null, fecha: (lc.autorizacion && lc.autorizacion.fechaLiquidacion) || null }
            : { hay: false, errores: (lc.errores && lc.errores.error) || null };
        }
        return J(200, { ok: true, pto: pe, representada: cuitRep, res: out });
      } catch (e) { return J(200, { ok: false, parcial: out, error: e.message }); }
    }

    // Consulta una liquidacion por COE (revela ptoEmision/nroOrden y confirma la representacion).
    if (action === 'granos_coe') {
      const sec = await getAfipSecrets();
      if (!sec.token || !sec.cert || !sec.key || !AFIP_CERT_CUIT) return J(200, { ok: false, error: 'Faltan secretos Afip.' });
      const coe = params && params.coe;
      if (!coe) return J(200, { ok: false, error: 'Falta coe.' });
      const cuitRep = (params && params.cuit) ? String(params.cuit) : AFIP_JOFA_CUIT;
      try {
        const r = await wslpgRequest('liquidacionXCoeConsultar', { coe: Number(coe), pdf: 'N' }, cuitRep);
        const lc = (r.data && (r.data.liqConsReturn || r.data)) || {};
        const L = lc.liquidacion || {};
        const err = (lc.errores && lc.errores.error) || null;
        return J(200, {
          ok: true, representada: cuitRep, status: r.status, errores: err,
          ptoEmision: L.ptoEmision != null ? L.ptoEmision : null, nroOrden: L.nroOrden != null ? L.nroOrden : null,
          cuitComprador: L.cuitComprador || null, cuitVendedor: L.cuitVendedor || null,
          normalizado: (lc.liquidacion || lc.autorizacion) ? normLiqGrano(lc, L.ptoEmision, L.nroOrden) : null,
        });
      } catch (e) { return J(200, { ok: false, error: e.message }); }
    }

    // Prueba de conexion/delegacion: ultimo nro por ptoEmision + una liquidacion de muestra.
    if (action === 'granos_debug') {
      const sec = await getAfipSecrets();
      if (!sec.token || !sec.cert || !sec.key || !AFIP_CERT_CUIT) return J(200, { ok: false, error: 'Faltan secretos Afip (cert/key/token via granos_secrets_set) o AFIP_CERT_CUIT.' });
      try {
        const out = { ok: true, representada: AFIP_JOFA_CUIT, cert: AFIP_CERT_CUIT, ptoEmis: {}, sample: null };
        for (const pe of AFIP_WSLPG_PTOEMIS) {
          const r = await wslpgRequest('liquidacionUltimoNroOrdenConsultar', { ptoEmision: pe });
          const ret = (r.data && (r.data.liqUltNroOrdenReturn || r.data)) || {};
          const nro = ret.nroOrden;
          const err = ret.errores && ret.errores.error;
          out.ptoEmis[pe] = { status: r.status, nroOrden: nro != null ? nro : null, errores: err || null };
          if (!out.sample && nro != null && Number(nro) >= 0) {
            const r2 = await wslpgRequest('liquidacionXNroOrdenConsultar', { ptoEmision: pe, nroOrden: Number(nro) });
            const lc = (r2.data && (r2.data.liqConsReturn || r2.data)) || {};
            if (lc.liquidacion || lc.autorizacion) {
              out.sample = { ptoEmision: pe, nroOrden: Number(nro), normalizado: normLiqGrano(lc, pe, Number(nro)), errores: (lc.errores && lc.errores.error) || null };
            }
          }
        }
        return J(200, out);
      } catch (e) { return J(200, { ok: false, error: e.message }); }
    }

    // Sincroniza nuevas liquidaciones (incremental, con tope para no exceder el timeout). Guarda en Blobs 'granos'.
    if (action === 'granos_sync') {
      { const sec = await getAfipSecrets(); if (!sec.token || !sec.cert || !sec.key || !AFIP_CERT_CUIT) return J(200, { ok: false, error: 'Faltan secretos Afip (cert/key/token via granos_secrets_set) o AFIP_CERT_CUIT.' }); }
      try {
        const limit = Math.min(Math.max(parseInt((params && params.limit) || 8, 10) || 8, 1), 25);
        const store = getCatStore();
        let g = (await store.get('granos', { type: 'json' })) || { updated: null, items: [], cursor: {} };
        if (!Array.isArray(g.items)) g.items = [];
        if (!g.cursor) g.cursor = {};
        const idx = {}; g.items.forEach((it) => { idx[it.ptoEmision + '-' + it.nroOrden] = true; });
        let fetched = 0; const progress = {};
        for (const pe of AFIP_WSLPG_PTOEMIS) {
          const r = await wslpgRequest('liquidacionUltimoNroOrdenConsultar', { ptoEmision: pe });
          const ret = (r.data && (r.data.liqUltNroOrdenReturn || r.data)) || {};
          const last = Number(ret.nroOrden) || 0;
          const from = (g.cursor[pe] != null ? g.cursor[pe] : -1) + 1; // nroOrden puede empezar en 0
          progress[pe] = { last: last, desde: from, traidas: 0 };
          for (let n = from; n <= last && fetched < limit; n++) {
            const r2 = await wslpgRequest('liquidacionXNroOrdenConsultar', { ptoEmision: pe, nroOrden: n });
            const lc = (r2.data && (r2.data.liqConsReturn || r2.data)) || {};
            if (lc && (lc.autorizacion || lc.liquidacion)) {
              if (!idx[pe + '-' + n]) { g.items.push(normLiqGrano(lc, pe, n)); idx[pe + '-' + n] = true; progress[pe].traidas++; }
            }
            g.cursor[pe] = n; fetched++;
          }
        }
        g.updated = new Date().toISOString();
        await store.setJSON('granos', g);
        return J(200, { ok: true, fetched: fetched, total: g.items.length, progress: progress, updated: g.updated });
      } catch (e) { return J(200, { ok: false, error: e.message }); }
    }

    // Devuelve las liquidaciones cacheadas (rapido, para el dashboard).
    if (action === 'granos_get') {
      try {
        const store = getCatStore();
        const g = (await store.get('granos', { type: 'json' })) || { items: [], updated: null };
        return J(200, { items: g.items || [], updated: g.updated || null });
      } catch (e) { return J(200, { items: [], _error: e.message }); }
    }

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
      case 'salidas_lotes': {
        // Listado de salidas de animales en lotes (ventas): price, supplier_name (comprador/frigorifico), invoice, DTA.
        // La API de eventos requiere apikey (no acepta el Bearer OAuth). Probamos combinaciones de auth en cascada.
        const outPath = '/events-farm-sitio2-3-default/v1/swine/farm/animal-group/output';
        const baseGw = WSO2_API_KEY ? { apikey: WSO2_API_KEY } : { 'Authorization': 'Bearer ' + gatewayToken };
        // Intento 1: apikey/gateway + token S4
        const h1 = { 'Content-Type': 'application/json', ...baseGw };
        if (s4AccessToken) h1['token'] = s4AccessToken;
        result = await makeRequest('POST', outPath, params, h1);
        // Intento 2: apikey + HTTP-AUTHORIZATION (token KPI)
        if (result.status === 401 || result.status === 403) {
          try {
            const kt = await getKpiToken();
            const h2 = { 'Content-Type': 'application/json', ...baseGw, 'HTTP-AUTHORIZATION': kt };
            const r2 = await makeRequest('POST', outPath, params, h2);
            if (r2.status !== 401 && r2.status !== 403) result = r2;
            else {
              // Intento 3: Bearer + token S4
              const h3 = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + gatewayToken };
              if (s4AccessToken) h3['token'] = s4AccessToken;
              const r3 = await makeRequest('POST', outPath, params, h3);
              if (r3.status !== 401 && r3.status !== 403) result = r3;
            }
          } catch (e) { console.error('salidas_lotes auth cascade error:', e.message); }
        }
        break;
      }
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
