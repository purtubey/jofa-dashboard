// Netlify Edge Function — Puerta de contrasena compartida para TODO el sitio (incluida /api/agriness).
// La contrasena se guarda en la variable de entorno SITE_PASSWORD (panel de Netlify).
// No es autenticacion por usuario: es una unica contrasena compartida. Nunca "falla abierto".

const COOKIE = "jofa_auth";
const MAX_AGE = 60 * 60 * 24 * 30; // 30 dias

async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}

function loginPage(msg, isError, configError) {
  const alert = configError
    ? '<div class="msg err">' + msg + "</div>"
    : (msg ? '<div class="msg ' + (isError ? "err" : "info") + '">' + msg + "</div>" : "");
  const form = configError
    ? ""
    : '<form method="POST" action="/__auth" autocomplete="off">' +
      '<label for="p">Contrasena</label>' +
      '<input id="p" name="password" type="password" autofocus required />' +
      '<button type="submit">Ingresar</button>' +
      "</form>";
  return (
    "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\" />" +
    '<meta name="viewport" content="width=device-width, initial-scale=1" />' +
    "<title>JOFA — Acceso</title><style>" +
    ":root{--bg:#0e1116;--card:#161b22;--border:#232a34;--text:#e6edf3;--muted:#8b98a5;--blue:#4f7df5;--red:#e85d5d;}" +
    "*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;" +
    "background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:20px}" +
    ".card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:32px;width:100%;max-width:360px;box-shadow:0 10px 40px rgba(0,0,0,.4)}" +
    ".brand{font-size:20px;font-weight:800;letter-spacing:.5px;margin-bottom:4px}" +
    ".sub{color:var(--muted);font-size:13px;margin-bottom:22px}" +
    "label{display:block;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}" +
    "input{width:100%;padding:12px 14px;border-radius:9px;border:1px solid var(--border);background:#0d1117;color:var(--text);font-size:15px;outline:none}" +
    "input:focus{border-color:var(--blue)}" +
    "button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-size:15px;font-weight:600;cursor:pointer}" +
    "button:hover{filter:brightness(1.08)}" +
    ".msg{padding:10px 12px;border-radius:8px;font-size:13px;margin-bottom:16px}" +
    ".msg.err{background:rgba(232,93,93,.12);color:var(--red);border:1px solid rgba(232,93,93,.35)}" +
    ".msg.info{background:rgba(79,125,245,.12);color:var(--blue);border:1px solid rgba(79,125,245,.3)}" +
    "</style></head><body><div class=\"card\">" +
    '<div class="brand">JOFA Porcinos</div>' +
    '<div class="sub">Panel de gestion — acceso restringido</div>' +
    alert + form +
    "</div></body></html>"
  );
}

export default async (request, context) => {
  const url = new URL(request.url);
  const PASSWORD = Netlify.env.get("SITE_PASSWORD");

  // Nunca falla abierto: si no hay contrasena configurada, bloquea todo.
  if (!PASSWORD) {
    return new Response(
      loginPage(
        "El sitio no esta configurado todavia. El dueno debe definir la variable de entorno SITE_PASSWORD en Netlify.",
        false, true
      ),
      { status: 503, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } }
    );
  }

  const token = await sha256("jofa|" + PASSWORD);
  const cookieOpts = "Path=/; Max-Age=" + MAX_AGE + "; HttpOnly; Secure; SameSite=Lax";

  // Cerrar sesion
  if (url.pathname === "/__logout") {
    return new Response(null, {
      status: 303,
      headers: { location: "/", "set-cookie": COOKIE + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" },
    });
  }

  // Enviar contrasena
  if (request.method === "POST" && url.pathname === "/__auth") {
    const form = await request.formData();
    const pw = String(form.get("password") || "");
    if (pw && (await sha256("jofa|" + pw)) === token) {
      return new Response(null, {
        status: 303,
        headers: { location: "/", "set-cookie": COOKIE + "=" + token + "; " + cookieOpts },
      });
    }
    return new Response(loginPage("Contrasena incorrecta. Proba de nuevo.", true), {
      status: 401, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
    });
  }

  // Ya autenticado -> seguir al sitio normal
  const cookies = parseCookies(request.headers.get("cookie"));
  if (cookies[COOKIE] === token) {
    return context.next();
  }

  // No autenticado -> mostrar login (bloquea tambien /api/agriness)
  return new Response(loginPage(null, false), {
    status: 401, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
};

// Configuracion inline: intercepta TODO el sitio. No requiere tocar netlify.toml.
export const config = { path: "/*" };
