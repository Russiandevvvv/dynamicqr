'use strict';
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({limit:'2mb'}));
const pool = new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL && /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL)?false:{rejectUnauthorized:false}});
const ready = pool.query(`CREATE TABLE IF NOT EXISTS qr_links (code VARCHAR(24) PRIMARY KEY, payload JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW())`);
ready.catch(e=>console.error('Banco indisponível:',e.message));
const codeValid = s => /^[a-zA-Z0-9_-]{6,24}$/.test(s||'');
function checkAuth(req,res,next){
 const h=req.headers.authorization||'';const expected=process.env.ADMIN_PASSWORD;
 if(!expected){return res.status(503).send('Configure ADMIN_PASSWORD no servidor.');}
 const raw=h.startsWith('Basic ')?Buffer.from(h.slice(6),'base64').toString('utf8'):'';
 const pass=raw.includes(':')?raw.slice(raw.indexOf(':')+1):'';
 const a=crypto.createHash('sha256').update(pass).digest();const b=crypto.createHash('sha256').update(expected).digest();
 if(!crypto.timingSafeEqual(a,b)){res.set('WWW-Authenticate','Basic realm="Painel QR"');return res.status(401).send('Acesso restrito');}
 next();
}
function validQr(q){if(!q||typeof q!=='object'||!codeValid(q.code)||!['static','dynamic'].includes(q.mode)||!['url','text','wifi','vcard','email','sms','pix'].includes(q.type))return false;
 if(q.mode==='dynamic'){if(q.type!=='url')return false;try{const u=new URL(q.data?.url);if(!['https:','http:'].includes(u.protocol)||!u.hostname.includes('.'))return false;}catch{return false;}}
 return true;}
app.get('/r/:code',async(req,res)=>{try{if(!codeValid(req.params.code))return res.status(404).send('QR Code não encontrado');await ready;const r=await pool.query('SELECT payload FROM qr_links WHERE code=$1',[req.params.code]);if(!r.rowCount)return res.status(404).send('QR Code não encontrado');const q=r.rows[0].payload;if(!q.active)return res.status(410).send('QR Code desativado');if(q.mode!=='dynamic'||q.type!=='url')return res.status(404).send('QR Code não encontrado');const u=new URL(q.data.url);if(!['http:','https:'].includes(u.protocol))return res.status(400).send('Destino inválido');res.set('Cache-Control','no-store, no-cache, must-revalidate');return res.redirect(302,u.href);}catch(e){console.error(e);res.status(503).send('Serviço temporariamente indisponível');}});
app.use('/api',checkAuth);
app.get('/api/qrs',async(req,res)=>{try{await ready;const r=await pool.query('SELECT payload FROM qr_links ORDER BY (payload->>\'createdAt\')::bigint DESC NULLS LAST');res.json(r.rows.map(x=>x.payload));}catch(e){res.status(503).json({error:'Erro ao carregar banco'});}});
app.post('/api/qrs',async(req,res)=>{const q=req.body;if(!validQr(q))return res.status(400).json({error:'Dados inválidos. QR dinâmico aceita URL.'});try{await ready;await pool.query('INSERT INTO qr_links(code,payload) VALUES($1,$2)',[q.code,JSON.stringify(q)]);res.status(201).json(q);}catch(e){res.status(e.code==='23505'?409:503).json({error:e.code==='23505'?'Código duplicado':'Erro ao salvar'});}});
app.put('/api/qrs/:code',async(req,res)=>{const q=req.body;if(!validQr(q)||q.code!==req.params.code)return res.status(400).json({error:'Dados inválidos'});try{await ready;const r=await pool.query('UPDATE qr_links SET payload=$2,updated_at=NOW() WHERE code=$1 RETURNING code',[q.code,JSON.stringify(q)]);if(!r.rowCount)return res.status(404).json({error:'QR não encontrado'});res.json(q);}catch(e){res.status(503).json({error:'Erro ao atualizar'});}});
app.delete('/api/qrs/:code',async(req,res)=>{if(!codeValid(req.params.code))return res.sendStatus(400);try{await ready;await pool.query('DELETE FROM qr_links WHERE code=$1',[req.params.code]);res.sendStatus(204);}catch(e){res.status(503).json({error:'Erro ao excluir'});}});
app.get('/api/config',(req,res)=>res.json({baseUrl:(process.env.PUBLIC_BASE_URL||`${req.protocol}://${req.get('host')}`).replace(/\/$/,'')}));
app.use(checkAuth,express.static(path.join(__dirname,'public'),{index:'index.html'}));
app.listen(process.env.PORT||3000,()=>console.log('Servidor QR ativo'));
