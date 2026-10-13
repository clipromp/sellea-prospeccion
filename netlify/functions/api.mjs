import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// ---------- utilidades ----------
const store = () => getStore({ name: "prospeccion", consistency: "strong" });
const SECRET = () => process.env.SESSION_SECRET || "";
const ahora = () => new Date().toISOString();
const DIA = 864e5;
const SESION_DIAS = 30;

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });

const b64 = (s) => Buffer.from(s).toString("base64url");
const firmar = (payload) => {
  const body = b64(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", SECRET()).update(body).digest("base64url");
  return body + "." + mac;
};
const verificar = (tok) => {
  if (!tok || !SECRET()) return null;
  const [body, mac] = tok.split(".");
  if (!body || !mac) return null;
  const esperado = crypto.createHmac("sha256", SECRET()).update(body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(esperado);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
};
const hashClave = (clave, salt = crypto.randomBytes(16).toString("hex")) =>
  "scrypt$" + salt + "$" + crypto.scryptSync(clave, salt, 32).toString("hex");
const claveOk = (clave, guardado) => {
  if (!guardado || !guardado.startsWith("scrypt$")) return false;
  const [, salt, h] = guardado.split("$");
  const calc = crypto.scryptSync(clave, salt, 32);
  const hb = Buffer.from(h, "hex");
  return hb.length === calc.length && crypto.timingSafeEqual(calc, hb);
};
const leerCookie = (req) => {
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)sp_sesion=([^;]+)/);
  return m ? m[1] : null;
};
const cookieSesion = (tok, maxAge) =>
  `sp_sesion=${tok}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

// Lectura-modificación-escritura protegida por etag (reintenta si otra persona escribió al mismo tiempo)
async function mutar(clave, fn) {
  const s = store();
  for (let i = 0; i < 6; i++) {
    const r = await s.getWithMetadata(clave, { type: "json" });
    const actual = r ? r.data : null;
    const siguiente = fn(actual ? structuredClone(actual) : null);
    const res = await s.setJSON(clave, siguiente, r ? { onlyIfMatch: r.etag } : { onlyIfNew: true });
    if (res.modified) return siguiente;
    await new Promise((ok) => setTimeout(ok, 80 + Math.random() * 200));
  }
  throw new Error("conflicto");
}

// ---------- usuarios ----------
async function usuariosGuardados() {
  return (await store().get("usuarios", { type: "json" })) || {};
}
async function todosLosUsuarios() {
  const u = await usuariosGuardados();
  const admin = (process.env.ADMIN_USUARIO || "").trim().toLowerCase();
  if (admin && process.env.ADMIN_CLAVE_HASH) {
    u[admin] = { nombre: process.env.ADMIN_NOMBRE || admin, rol: "admin", hash: process.env.ADMIN_CLAVE_HASH, fijo: true };
  }
  return u;
}

// ---------- datos ----------
const CAMPOS = ["negocio", "instagram", "pais", "rubro", "mensaje", "etapa", "nota", "seguimientos", "historial", "ultimoContacto", "nuevoMensaje", "origen"];
const ETAPAS = ["calentado", "dm", "respondio", "agendada", "presentada", "cerro", "no"];
function limpiar(d = {}) {
  const out = {};
  for (const k of CAMPOS) {
    if (!(k in d)) continue;
    const v = d[k];
    if (k === "seguimientos") out[k] = Math.max(0, Math.min(10, Number(v) || 0));
    else if (k === "historial") {
      const h = {};
      if (v && typeof v === "object") for (const e of ETAPAS) if (typeof v[e] === "string") h[e] = v[e].slice(0, 40);
      out[k] = h;
    } else if (k === "etapa") { if (ETAPAS.includes(v)) out[k] = v; }
    else if (k === "nuevoMensaje") out[k] = !!v;
    else if (k === "origen") { if (["prospectado", "entrante"].includes(v)) out[k] = v; }
    else out[k] = String(v ?? "").slice(0, k === "nota" ? 1000 : 200);
  }
  return out;
}
async function leerDatos() {
  const s = store();
  const [p, m] = await Promise.all([s.get("prospectos", { type: "json" }), s.get("mensajes", { type: "json" })]);
  const lista = Object.values(p?.items || {}).sort((a, b) => (b.actualizado || "").localeCompare(a.actualizado || ""));
  return { prospectos: lista, mensajes: m || {} };
}

// ---------- registro de actividad ----------
// Un documento por mes: log/AAAA-MM con { entradas: [...] }
async function registrar(me, accion, extra = {}) {
  const t = ahora();
  const e = { t, u: me.usuario, nombre: me.nombre, accion, ...extra };
  try {
    await mutar("log/" + t.slice(0, 7), (cur) => {
      cur = cur || { entradas: [] };
      cur.entradas.push(e);
      if (cur.entradas.length > 20000) cur.entradas = cur.entradas.slice(-20000);
      return cur;
    });
  } catch (err) { console.error("No se pudo registrar la actividad", err); }
}
const CAMPOS_LOG = ["negocio", "instagram", "pais", "rubro", "mensaje", "etapa", "nota", "seguimientos"];
function diferencias(antes = {}, despues = {}) {
  const c = {};
  for (const k of CAMPOS_LOG) {
    const a = antes[k] ?? null, d = despues[k] ?? null;
    if (JSON.stringify(a) !== JSON.stringify(d)) c[k] = [a, d];
  }
  return c;
}

// ---------- Instagram: avisos de Meta (webhook) ----------
// Variables en Netlify: META_VERIFY_TOKEN, META_APP_SECRET, IG_ACCESS_TOKEN y, opcional, IG_API_BASE
const INSTAGRAM = { usuario: "instagram", nombre: "Instagram" };
const ORDEN = { calentado: 0, dm: 1, respondio: 2, agendada: 3, presentada: 4, cerro: 5 };
function historialHasta(h = {}, etapa, cuando) {
  h = { ...h };
  if (etapa === "no") { h.no = h.no || cuando; return h; }
  for (const e of Object.keys(ORDEN)) if (ORDEN[e] <= ORDEN[etapa] && !h[e]) h[e] = cuando;
  return h;
}
const igApi = () => (process.env.IG_API_BASE || "https://graph.instagram.com/v23.0").replace(/\/$/, "");
async function perfilIG(igsid) {
  const tok = process.env.IG_ACCESS_TOKEN;
  if (!tok) return null;
  try {
    const r = await fetch(`${igApi()}/${encodeURIComponent(igsid)}?fields=username,name&access_token=${encodeURIComponent(tok)}`);
    if (!r.ok) { console.error("Perfil de Instagram", r.status, (await r.text()).slice(0, 300)); return null; }
    return await r.json();
  } catch (e) { console.error("Perfil de Instagram", e); return null; }
}
function firmaMetaOk(cuerpoCrudo, cabecera) {
  const secreto = process.env.META_APP_SECRET;
  if (!secreto || !cabecera) return false;
  const esperado = "sha256=" + crypto.createHmac("sha256", secreto).update(cuerpoCrudo).digest("hex");
  const a = Buffer.from(cabecera), b = Buffer.from(esperado);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function procesarMensajeIG(igsid, eco, texto, ts) {
  const cuando = new Date(ts || Date.now()).toISOString();
  const items = (await store().get("prospectos", { type: "json" }))?.items || {};
  let it = Object.values(items).find((x) => x.igsid === igsid);
  let perfil = null;
  if (!it) {
    perfil = await perfilIG(igsid);
    const user = (perfil?.username || "").toLowerCase();
    if (user) it = Object.values(items).find((x) => (x.instagram || "").toLowerCase().replace(/^@/, "") === user);
  }
  if (eco) {
    // Mensaje que salió de @selleala: solo cuenta si ese negocio ya está en el CRM
    if (!it) return;
    let antes = null, despues = null;
    await mutar("prospectos", (cur) => {
      const x = cur?.items?.[it.id];
      if (!x) return cur;
      antes = x;
      const cambios = { igsid, ultimoContacto: cuando };
      if (x.etapa === "calentado") { cambios.etapa = "dm"; cambios.historial = historialHasta(x.historial, "dm", cuando); }
      despues = cur.items[it.id] = { ...x, ...cambios, actualizado: ahora() };
      return cur;
    });
    if (antes && antes.etapa !== despues.etapa) await registrar(INSTAGRAM, "edito", { id: it.id, negocio: it.negocio, cambios: { etapa: [antes.etapa, despues.etapa] } });
    return;
  }
  if (it) {
    let antes = null, despues = null;
    await mutar("prospectos", (cur) => {
      const x = cur?.items?.[it.id];
      if (!x) return cur;
      antes = x;
      const cambios = { igsid, nuevoMensaje: true, ultimoMensaje: cuando };
      if (x.etapa === "calentado" || x.etapa === "dm") { cambios.etapa = "respondio"; cambios.historial = historialHasta(x.historial, "respondio", cuando); }
      despues = cur.items[it.id] = { ...x, ...cambios, actualizado: ahora() };
      return cur;
    });
    if (antes && antes.etapa !== despues.etapa) await registrar(INSTAGRAM, "edito", { id: it.id, negocio: it.negocio, cambios: { etapa: [antes.etapa, despues.etapa] } });
    else if (antes) await registrar(INSTAGRAM, "mensaje-ig", { id: it.id, negocio: it.negocio });
    return;
  }
  // Alguien nuevo le escribió a @selleala por su cuenta
  const id = crypto.randomUUID();
  const nuevo = {
    id, negocio: perfil?.name || perfil?.username || "Contacto de Instagram", instagram: perfil?.username || "", igsid,
    origen: "entrante", etapa: "respondio", historial: { respondio: cuando }, seguimientos: 0,
    nuevoMensaje: true, ultimoMensaje: cuando, nota: texto ? "Primer mensaje: " + texto.slice(0, 200) : "",
    creado: ahora(), actualizado: ahora(), por: INSTAGRAM.usuario, porNombre: INSTAGRAM.nombre,
  };
  await mutar("prospectos", (cur) => { cur = cur || { items: {} }; if (!Object.values(cur.items).some((x) => x.igsid === igsid)) cur.items[id] = nuevo; return cur; });
  await registrar(INSTAGRAM, "creo", { id, negocio: nuevo.negocio, etapa: nuevo.etapa });
}

// ---------- rutas ----------
export default async (req) => {
  const url = new URL(req.url);
  const ruta = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const metodo = req.method;
  const cuerpo = async () => (metodo === "POST" ? await req.json().catch(() => ({})) : {});

  if (!SECRET()) return json({ error: "Falta configurar SESSION_SECRET en Netlify." }, 500);

  try {
    // Exportación de solo lectura para análisis (protegida con EXPORT_KEY)
    if (ruta === "export" && metodo === "GET") {
      const k = url.searchParams.get("key") || "";
      const esperado = process.env.EXPORT_KEY || "";
      if (!esperado || k.length !== esperado.length || !crypto.timingSafeEqual(Buffer.from(k), Buffer.from(esperado)))
        return json({ error: "No autorizado" }, 401);
      return json({ generado: ahora(), ...(await leerDatos()) });
    }

    // Webhook de Meta para los DMs de @selleala (no usa sesión: se valida con la firma de Meta)
    if (ruta === "instagram") {
      if (metodo === "GET") {
        const p = url.searchParams;
        const tok = process.env.META_VERIFY_TOKEN || "";
        if (p.get("hub.mode") === "subscribe" && tok && p.get("hub.verify_token") === tok)
          return new Response(p.get("hub.challenge") || "", { status: 200, headers: { "content-type": "text/plain" } });
        return new Response("Token de verificación incorrecto", { status: 403 });
      }
      if (metodo === "POST") {
        const crudo = await req.text();
        if (!firmaMetaOk(crudo, req.headers.get("x-hub-signature-256"))) return new Response("Firma no válida", { status: 401 });
        let body = {};
        try { body = JSON.parse(crudo); } catch { return new Response("ok"); }
        for (const entry of body.entry || []) {
          for (const ev of entry.messaging || []) {
            if (!ev.message || ev.message.is_deleted) continue;
            const eco = !!ev.message.is_echo;
            const igsid = eco ? ev.recipient?.id : ev.sender?.id;
            if (!igsid || igsid === entry.id) continue;
            try { await procesarMensajeIG(igsid, eco, ev.message.text || "", ev.timestamp); }
            catch (e) { console.error("Webhook de Instagram", e); }
          }
        }
        return new Response("ok");
      }
    }

    if (ruta === "login" && metodo === "POST") {
      const b = await cuerpo();
      const usuario = String(b.usuario || "").trim().toLowerCase();
      const u = (await todosLosUsuarios())[usuario];
      if (!u || !claveOk(String(b.clave || ""), u.hash)) {
        await new Promise((ok) => setTimeout(ok, 700));
        return json({ error: "Usuario o contraseña incorrectos." }, 401);
      }
      await registrar({ usuario, nombre: u.nombre }, "entro");
      const tok = firmar({ u: usuario, exp: Date.now() + SESION_DIAS * DIA });
      return json({ usuario, nombre: u.nombre, rol: u.rol }, 200, { "set-cookie": cookieSesion(tok, SESION_DIAS * 86400) });
    }

    if (ruta === "logout") return json({ ok: true }, 200, { "set-cookie": cookieSesion("", 0) });

    // A partir de aquí todo requiere sesión
    const ses = verificar(leerCookie(req));
    const usuarios = ses ? await todosLosUsuarios() : {};
    const yo = ses && usuarios[ses.u];
    if (!yo) return json({ error: "Tu sesión venció. Vuelve a entrar." }, 401);
    const me = { usuario: ses.u, nombre: yo.nombre, rol: yo.rol };

    if (ruta === "yo") return json(me);
    if (ruta === "datos" && metodo === "GET") return json(await leerDatos());

    if (ruta === "prospectos" && metodo === "POST") {
      const b = await cuerpo();
      const datos = limpiar(b.datos);
      let antes = null, despues = null;
      await mutar("prospectos", (cur) => {
        cur = cur || { items: {} };
        if (b.accion === "crear") {
          if (!datos.negocio) throw Object.assign(new Error("Falta el nombre del negocio."), { status: 400 });
          const id = crypto.randomUUID();
          antes = null;
          despues = cur.items[id] = { seguimientos: 0, historial: {}, ...datos, id, creado: ahora(), actualizado: ahora(), por: me.usuario, porNombre: me.nombre };
        } else if (b.accion === "actualizar") {
          const it = cur.items[b.id];
          if (!it) throw Object.assign(new Error("Ese prospecto ya no existe."), { status: 404 });
          antes = it;
          despues = cur.items[b.id] = { ...it, ...datos, actualizado: ahora() };
        } else if (b.accion === "borrar") {
          const it = cur.items[b.id];
          if (!it) throw Object.assign(new Error("Ese prospecto ya no existe."), { status: 404 });
          antes = it; despues = null;
          delete cur.items[b.id];
        } else throw Object.assign(new Error("Acción no válida."), { status: 400 });
        return cur;
      });
      if (b.accion === "crear") {
        await registrar(me, "creo", { id: despues.id, negocio: despues.negocio, etapa: despues.etapa });
      } else if (b.accion === "actualizar") {
        const cambios = diferencias(antes, despues);
        if (Object.keys(cambios).length) await registrar(me, "edito", { id: despues.id, negocio: despues.negocio, cambios });
      } else if (b.accion === "borrar") {
        // Nada se pierde: lo borrado pasa a la papelera
        await mutar("papelera", (cur) => {
          cur = cur || { items: {} };
          cur.items[antes.id] = { ...antes, borrado: ahora(), borradoPor: me.usuario, borradoPorNombre: me.nombre };
          return cur;
        });
        await registrar(me, "borro", { id: antes.id, negocio: antes.negocio, etapa: antes.etapa });
      }
      return json(await leerDatos());
    }

    if (ruta === "mensajes" && metodo === "POST") {
      const b = await cuerpo();
      const n = String(b.n || "");
      if (!["1", "2", "3", "4", "5"].includes(n)) return json({ error: "Número de mensaje no válido." }, 400);
      let anterior = "";
      const texto = String(b.texto || "").slice(0, 2000);
      await mutar("mensajes", (cur) => { anterior = (cur && cur["m" + n]) || ""; return { ...(cur || {}), ["m" + n]: texto, actualizado: ahora() }; });
      if (anterior !== texto) await registrar(me, "mensaje", { n, cambios: { texto: [anterior, texto] } });
      return json(await leerDatos());
    }

    if (ruta === "actividad" && metodo === "GET") {
      if (yo.rol !== "admin") return json({ error: "Solo el administrador puede ver la actividad." }, 403);
      const mes = /^\d{4}-\d{2}$/.test(url.searchParams.get("mes") || "") ? url.searchParams.get("mes") : ahora().slice(0, 7);
      const doc = await store().get("log/" + mes, { type: "json" });
      return json({ mes, entradas: (doc?.entradas || []).slice().reverse() });
    }

    if (ruta === "papelera") {
      if (yo.rol !== "admin") return json({ error: "Solo el administrador puede ver la papelera." }, 403);
      const listar = async () => Object.values((await store().get("papelera", { type: "json" }))?.items || {})
        .sort((a, c) => (c.borrado || "").localeCompare(a.borrado || ""));
      if (metodo === "GET") return json(await listar());
      const b = await cuerpo();
      let item = null;
      await mutar("papelera", (cur) => {
        cur = cur || { items: {} };
        item = cur.items[b.id];
        if (!item) throw Object.assign(new Error("Ese prospecto ya no está en la papelera."), { status: 404 });
        delete cur.items[b.id];
        return cur;
      });
      if (b.accion === "restaurar") {
        const { borrado, borradoPor, borradoPorNombre, ...limpio } = item;
        await mutar("prospectos", (cur) => { cur = cur || { items: {} }; cur.items[limpio.id] = { ...limpio, actualizado: ahora() }; return cur; });
        await registrar(me, "restauro", { id: item.id, negocio: item.negocio });
      } else {
        await registrar(me, "elimino", { id: item.id, negocio: item.negocio });
      }
      return json({ papelera: await listar(), ...(await leerDatos()) });
    }

    if (ruta === "usuarios") {
      if (yo.rol !== "admin") return json({ error: "Solo el administrador puede manejar usuarios." }, 403);
      const lista = (us) => Object.entries(us).map(([usuario, u]) => ({ usuario, nombre: u.nombre, rol: u.rol, fijo: !!u.fijo }))
        .sort((a, b) => a.usuario.localeCompare(b.usuario));
      if (metodo === "GET") return json(lista(usuarios));
      const b = await cuerpo();
      const usuario = String(b.usuario || "").trim().toLowerCase();
      if (!/^[a-z0-9._-]{3,30}$/.test(usuario)) return json({ error: "El usuario debe tener de 3 a 30 letras minúsculas, números, punto o guion." }, 400);
      if (usuarios[usuario]?.fijo) return json({ error: "Ese usuario es el administrador principal; se cambia desde Netlify." }, 400);
      if ((b.accion === "crear" || b.accion === "clave") && String(b.clave || "").length < 8)
        return json({ error: "La contraseña debe tener al menos 8 caracteres." }, 400);
      await mutar("usuarios", (cur) => {
        cur = cur || {};
        if (b.accion === "crear") {
          if (cur[usuario]) throw Object.assign(new Error("Ese usuario ya existe."), { status: 400 });
          cur[usuario] = { nombre: String(b.nombre || usuario).slice(0, 60), rol: b.rol === "admin" ? "admin" : "prospectora", hash: hashClave(String(b.clave)) };
        } else if (b.accion === "clave") {
          if (!cur[usuario]) throw Object.assign(new Error("Ese usuario no existe."), { status: 404 });
          cur[usuario].hash = hashClave(String(b.clave));
        } else if (b.accion === "borrar") {
          if (usuario === me.usuario) throw Object.assign(new Error("No puedes borrar tu propio usuario."), { status: 400 });
          delete cur[usuario];
        } else throw Object.assign(new Error("Acción no válida."), { status: 400 });
        return cur;
      });
      await registrar(me, "usuario-" + b.accion, { usuarioAfectado: usuario });
      return json(lista(await todosLosUsuarios()));
    }

    return json({ error: "No encontrado" }, 404);
  } catch (e) {
    if (e && e.status) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: e?.message === "conflicto" ? "Hubo un choque al guardar. Intenta de nuevo." : "Error del servidor." }, 500);
  }
};

export const config = { path: "/api/*" };
