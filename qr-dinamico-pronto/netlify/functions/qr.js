'use strict';
const { Pool } = require('pg');
const crypto = require('crypto');
let pool;
let ready;
function db() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL não configurada');
  if (!pool) {
    pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2, connectionTimeoutMillis: 10000, idleTimeoutMillis: 10000 });
    ready = pool.query('CREATE TABLE IF NOT EXISTS qr_links (code VARCHAR(24) PRIMARY KEY, payload JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW())').catch(e => {ready = null; throw e;});
  }
  return ready;
}
const json = (statusCode, value, headers={}) => ({statusCode,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers},body:JSON.stringify(value)});
const message = (statusCode, value, headers={}) => ({statusCode,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store',...headers},body:value});
const validCode = code => /^[a-zA-Z0-9_-]{6,24}$/.test(code||'');
function validQr(q) {
  if (!q || typeof q !== 'object' || !validCode(q.code) || !['static','dynamic'].includes(q.mode) || !['url','text','wifi','vcard','email','sms','pix'].includes(q.type)) return false;
  if (q.mode === 'dynamic') {
    if (q.type !== 'url') return false;
    try {const u = new URL(q.data?.url); if (!['https:','http:'].includes(u.protocol) || !u.hostname.includes('.')) return false;} catch {return false;}
  }
  return true;
}
function auth(event) {
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) return message(503,'Configure ADMIN_PASSWORD no Netlify');
  const h = event.headers.authorization || event.headers.Authorization || '';
  let raw = '';
  try {raw = h.startsWith('Basic ') ? Buffer.from(h.slice(6),'base64').toString('utf8') : '';} catch {}
  const pass = raw.includes(':') ? raw.slice(raw.indexOf(':')+1) : '';
  const a = crypto.createHash('sha256').update(pass).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a,b) ? null : message(401,'Acesso restrito',{'WWW-Authenticate':'Basic realm="Painel QR"'});
}
exports.handler = async event => {
  const qs = event.queryStringParameters || {};
  const path = (event.path || '').split('?')[0];
  const match = path.match(/\/(?:api\/qrs|r|redirect|item)\/([^/]+)$/);
  const code = qs.code || (match ? decodeURIComponent(match[1]) : undefined);
  const kind = qs.kind || ((/\/(?:r|redirect)\/[^/]+$/.test(path)) ? 'redirect' : /\/(?:api\/config|config)$/.test(path) ? 'config' : /\/(?:api\/qrs|list)$/.test(path) ? 'qrs' : /\/(?:api\/qrs|item)\/[^/]+$/.test(path) ? 'qr' : undefined);
  const method = event.httpMethod;
  try {
    if (kind === 'redirect') {
      if (method !== 'GET' || !validCode(code)) return message(404,'QR Code não encontrado');
      await db();
      const r = await pool.query('SELECT payload FROM qr_links WHERE code=$1',[code]);
      if (!r.rowCount) return message(404,'QR Code não encontrado');
      const q = r.rows[0].payload;
      if (!q.active) return message(410,'QR Code desativado');
      if (q.mode !== 'dynamic' || q.type !== 'url') return message(404,'QR Code não encontrado');
      const url = new URL(q.data.url);
      if (!['https:','http:'].includes(url.protocol)) return message(400,'Destino inválido');
      return {statusCode:302,headers:{Location:url.href,'Cache-Control':'no-store'},body:''};
    }
    if (kind === 'config') {
      if (method !== 'GET') return message(405,'Método não permitido');
      const proto = (event.headers['x-forwarded-proto'] || 'https').split(',')[0];
      const host = event.headers['x-forwarded-host'] || event.headers.host;
      return json(200,{baseUrl:(process.env.PUBLIC_BASE_URL || `${proto}://${host}`).replace(/\/$/,'')});
    }
    if (!['qrs','qr'].includes(kind)) return message(404,'Rota não encontrada');
    const denied = auth(event);
    if (denied) return denied;
    await db();
    if (kind === 'qrs' && method === 'GET') {
      const r = await pool.query("SELECT payload FROM qr_links ORDER BY (payload->>'createdAt')::bigint DESC NULLS LAST");
      return json(200,r.rows.map(x=>x.payload));
    }
    if (kind === 'qrs' && method === 'POST') {
      const q = JSON.parse(event.body || '{}');
      if (!validQr(q)) return json(400,{error:'Dados inválidos. QR dinâmico aceita URL.'});
      try {await pool.query('INSERT INTO qr_links(code,payload) VALUES($1,$2)',[q.code,JSON.stringify(q)]);}
      catch(e) {if(e.code==='23505')return json(409,{error:'Código duplicado'});throw e;}
      return json(201,q);
    }
    if (kind === 'qr' && !validCode(code)) return json(400,{error:'Código inválido'});
    if (kind === 'qr' && method === 'PUT') {
      const q = JSON.parse(event.body || '{}');
      if (!validQr(q) || q.code !== code) return json(400,{error:'Dados inválidos'});
      const r = await pool.query('UPDATE qr_links SET payload=$2,updated_at=NOW() WHERE code=$1 RETURNING code',[code,JSON.stringify(q)]);
      return r.rowCount ? json(200,q) : json(404,{error:'QR não encontrado'});
    }
    if (kind === 'qr' && method === 'DELETE') {
      await pool.query('DELETE FROM qr_links WHERE code=$1',[code]);
      return {statusCode:204,body:''};
    }
    return message(405,'Método não permitido');
  } catch(e) {
    console.error('Erro na função QR:',e);
    return json(503,{error:'Erro de conexão ou processamento. Verifique as configurações e os logs.'});
  }
};
