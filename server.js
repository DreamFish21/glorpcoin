const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = __dirname;
const types = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.svg':'image/svg+xml'};
const clients = new Set();
const game = {marketState:'waiting',marketPrice:50,priceHistory:[],players:[],marketStartedAt:0,nextPriceTickAt:0,marketEndsAt:0};
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

function json(res,status,payload){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(payload))}
function sendEvent(client,name,payload){if(!client.res.destroyed)client.res.write(`event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`)}
function playerState(login){const player=game.players.find(item=>item.name.toLowerCase()===login);return {marketState:game.marketState,marketPrice:game.marketPrice,priceHistory:game.priceHistory,marketStartedAt:game.marketStartedAt,nextPriceTickAt:game.nextPriceTickAt,marketEndsAt:game.marketEndsAt,priceTickMs:8000,player:player?{name:player.name,spriteId:player.spriteId,points:player.points,coins:player.coins}:null}}
function publishState(){for(const client of clients)if(client.role==='viewer')sendEvent(client,'state',playerState(client.login))}
function readJson(req){return new Promise((resolve,reject)=>{let body='';req.on('data',chunk=>{body+=chunk;if(body.length>1_000_000){reject(new Error('Request too large'));req.destroy()}});req.on('end',()=>{try{resolve(JSON.parse(body||'{}'))}catch{reject(new Error('Invalid JSON'))}});req.on('error',reject)})}
function signature(value){return crypto.createHmac('sha256',sessionSecret).update(value).digest('base64url')}
function signObject(value){const body=Buffer.from(JSON.stringify(value)).toString('base64url');return `${body}.${signature(body)}`}
function verifyObject(value){if(typeof value!=='string')return null;const [body,provided]=value.split('.');if(!body||!provided)return null;const expected=signature(body),a=Buffer.from(provided),b=Buffer.from(expected);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;try{const data=JSON.parse(Buffer.from(body,'base64url').toString('utf8'));return data.exp>Date.now()?data:null}catch{return null}}
function getCookie(req,name){const cookies=(req.headers.cookie||'').split(';');for(const item of cookies){const separator=item.indexOf('=');if(separator<0)continue;if(item.slice(0,separator).trim()===name)return decodeURIComponent(item.slice(separator+1).trim())}return null}
function getSession(req){return verifyObject(getCookie(req,'dropin_session'))}
function appendCookie(res,value){const current=res.getHeader('Set-Cookie');res.setHeader('Set-Cookie',[...(Array.isArray(current)?current:current?[current]:[]),value])}
function publicBase(req){const configured=process.env.PUBLIC_BASE_URL||process.env.RENDER_EXTERNAL_URL;if(configured)return configured.replace(/\/+$/,'');const protocol=req.headers['x-forwarded-proto']||'http';return `${protocol}://${req.headers.host||`localhost:${process.env.PORT||3001}`}`.replace(/\/+$/,'')}
function secureCookie(req){return publicBase(req).startsWith('https://')?'; Secure':''}
function setCookie(res,req,name,value,maxAge){appendCookie(res,`${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureCookie(req)}`)}
function clearCookie(res,req,name){appendCookie(res,`${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureCookie(req)}`)}
function safeReturnPath(value){return typeof value==='string'&&value.startsWith('/')&&!value.startsWith('//')?value:'/player.html'}
function redirectAuthError(req,res,returnPath,error){const url=new URL(safeReturnPath(returnPath),publicBase(req));url.searchParams.set('auth',error);res.writeHead(302,{Location:url.toString(),'Cache-Control':'no-store'});res.end()}
function isHost(req){if(process.env.NODE_ENV!=='production')return true;const session=getSession(req),broadcaster=(process.env.BROADCASTER_LOGIN||'').trim().toLowerCase();return Boolean(session?.host||session?.login&&broadcaster&&session.login.toLowerCase()===broadcaster)}
function serveFile(pathname,res){const relative=pathname==='/'?'index.html':pathname.replace(/^\/+/, '');const file=path.resolve(root,relative);if(!file.startsWith(root+path.sep)&&file!==path.join(root,'index.html')){res.writeHead(403);res.end('Forbidden');return}fs.readFile(file,(error,data)=>{if(error){res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Not found');return}res.writeHead(200,{'Content-Type':types[path.extname(file)]||'application/octet-stream','Cache-Control':'no-store'});res.end(data)})}

http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://localhost'),pathname=decodeURIComponent(url.pathname);
  if(req.method==='GET'&&pathname==='/health')return json(res,200,{ok:true});
  if(req.method==='POST'&&pathname==='/auth/host'){
    if(!process.env.HOST_PASSWORD)return json(res,503,{error:'Вход стримера не настроен в Render.'});
    let data;try{data=await readJson(req)}catch(error){return json(res,400,{error:error.message})}
    const provided=Buffer.from(String(data.password||'')),expected=Buffer.from(process.env.HOST_PASSWORD);
    if(provided.length!==expected.length||!crypto.timingSafeEqual(provided,expected))return json(res,401,{error:'Неверный пароль стримера.'});
    setCookie(res,req,'dropin_session',signObject({host:true,exp:Date.now()+12*60*60*1000}),12*60*60);return json(res,200,{ok:true})
  }
  if(req.method==='GET'&&pathname==='/auth/twitch'){
    if(!process.env.TWITCH_CLIENT_ID||!process.env.TWITCH_CLIENT_SECRET)return redirectAuthError(req,res,url.searchParams.get('return'),'unconfigured');
    const state=crypto.randomBytes(24).toString('base64url'),returnPath=safeReturnPath(url.searchParams.get('return')),payload=signObject({state,returnPath,exp:Date.now()+10*60*1000}),redirectUri=new URL('/auth/twitch/callback',publicBase(req)).toString();setCookie(res,req,'dropin_oauth',payload,600);
    const authorize=new URL('https://id.twitch.tv/oauth2/authorize');authorize.searchParams.set('client_id',process.env.TWITCH_CLIENT_ID);authorize.searchParams.set('redirect_uri',redirectUri);authorize.searchParams.set('response_type','code');authorize.searchParams.set('state',state);res.writeHead(302,{Location:authorize.toString(),'Cache-Control':'no-store'});return res.end()
  }
  if(req.method==='GET'&&pathname==='/auth/twitch/callback'){
    const pending=verifyObject(getCookie(req,'dropin_oauth')),returnPath=pending?.returnPath||'/player.html',error=url.searchParams.get('error'),code=url.searchParams.get('code'),state=url.searchParams.get('state');
    if(error||!pending||!code||state!==pending.state){clearCookie(res,req,'dropin_oauth');return redirectAuthError(req,res,returnPath,error==='access_denied'?'denied':'failed')}
    try{
      const redirectUri=new URL('/auth/twitch/callback',publicBase(req)).toString(),body=new URLSearchParams({client_id:process.env.TWITCH_CLIENT_ID,client_secret:process.env.TWITCH_CLIENT_SECRET,code,grant_type:'authorization_code',redirect_uri:redirectUri}),tokenResponse=await fetch('https://id.twitch.tv/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}),token=await tokenResponse.json();
      if(!tokenResponse.ok||!token.access_token)throw new Error('Token exchange failed');
      const validationResponse=await fetch('https://id.twitch.tv/oauth2/validate',{headers:{Authorization:`OAuth ${token.access_token}`}}),identity=await validationResponse.json();
      if(!validationResponse.ok||identity.client_id!==process.env.TWITCH_CLIENT_ID||!identity.login||!identity.user_id)throw new Error('Identity validation failed');
      const session=signObject({login:identity.login,userId:identity.user_id,exp:Date.now()+12*60*60*1000});setCookie(res,req,'dropin_session',session,12*60*60);clearCookie(res,req,'dropin_oauth');const target=new URL(safeReturnPath(returnPath),publicBase(req));target.searchParams.set('auth','connected');res.writeHead(302,{Location:target.toString(),'Cache-Control':'no-store'});return res.end()
    }catch{clearCookie(res,req,'dropin_oauth');clearCookie(res,req,'dropin_session');return redirectAuthError(req,res,returnPath,'failed')}
  }
  if(req.method==='GET'&&pathname==='/auth/twitch/logout'){clearCookie(res,req,'dropin_session');const target=new URL(safeReturnPath(url.searchParams.get('return')),publicBase(req));res.writeHead(302,{Location:target.toString(),'Cache-Control':'no-store'});return res.end()}
  if(req.method==='GET'&&pathname==='/api/me'){const session=getSession(req);return json(res,200,{authenticated:Boolean(session?.login),login:session?.login||null,isHost:session?isHost(req):false})}
  if(req.method==='GET'&&pathname==='/api/state'){const login=getSession(req)?.login||(url.searchParams.get('login')||'').trim().toLowerCase();return json(res,200,playerState(login))}
  if(req.method==='GET'&&pathname==='/api/events'){
    const role=url.searchParams.get('role')==='host'?'host':'viewer',login=getSession(req)?.login||(url.searchParams.get('login')||'').trim().toLowerCase();
    if(role==='host'&&!isHost(req))return json(res,403,{error:'Для управления рынком войди на Twitch как владелец канала.'});
    if(role==='viewer'&&!login)return json(res,400,{error:'Укажите Twitch-ник'});
    res.writeHead(200,{'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-cache, no-transform','Connection':'keep-alive','X-Accel-Buffering':'no'});res.write('retry: 2000\n\n');const client={res,role,login};clients.add(client);if(role==='viewer')sendEvent(client,'state',playerState(login));res.on('close',()=>clients.delete(client));return
  }
  if(req.method==='POST'&&pathname==='/api/snapshot'){
    if(!isHost(req))return json(res,403,{error:'Для публикации состояния войди на Twitch как владелец канала.'});
    try{const data=await readJson(req);game.marketState=['waiting','running','finished'].includes(data.marketState)?data.marketState:'waiting';game.marketPrice=Number.isFinite(Number(data.marketPrice))?Number(data.marketPrice):50;game.priceHistory=Array.isArray(data.priceHistory)?data.priceHistory.slice(-80).map(Number).filter(Number.isFinite):[];game.marketStartedAt=Number(data.marketStartedAt)||0;game.nextPriceTickAt=Number(data.nextPriceTickAt)||0;game.marketEndsAt=Number(data.marketEndsAt)||0;game.players=Array.isArray(data.players)?data.players.slice(0,100).filter(player=>typeof player.name==='string').map(player=>({name:player.name.slice(0,25),spriteId:Math.max(1,Math.min(50,Number(player.spriteId)||1)),points:Number(player.points)||0,coins:Number(player.coins)||0})):[];publishState();return json(res,200,{ok:true})}catch(error){return json(res,error.message==='Invalid JSON'?400:413,{error:error.message})}
  }
  if(req.method==='POST'&&pathname==='/api/trade'){
    let data;try{data=await readJson(req)}catch(error){return json(res,400,{error:error.message})}
    const session=getSession(req);if(process.env.REQUIRE_TWITCH_LOGIN==='true'&&!session?.login)return json(res,401,{error:'Сначала войди через Twitch.'});const login=session?.login||(typeof data.login==='string'?data.login.trim().toLowerCase():''),type=data.type,quantity=Number(data.quantity),player=game.players.find(item=>item.name.toLowerCase()===login);
    if(!player)return json(res,404,{error:'Участник не найден. Проверь Twitch-ник или сначала напиши !glorp в чате.'});
    if(game.marketState!=='running')return json(res,409,{error:'Торги сейчас закрыты.'});
    if(!['buy','sell'].includes(type)||!Number.isFinite(quantity)||quantity<=0||quantity>1_000_000)return json(res,400,{error:'Укажи количество больше нуля.'});
    if(type==='buy'&&quantity*game.marketPrice>player.points+.0001)return json(res,409,{error:'Не хватает points для покупки.'});
    if(type==='sell'&&quantity>player.coins+.0001)return json(res,409,{error:`У тебя только ${player.coins} GC.`});
    const hosts=[...clients].filter(client=>client.role==='host'&&!client.res.destroyed);if(!hosts.length)return json(res,503,{error:'Игра не подключена к серверу. Обнови основную страницу рынка.'});
    const trade={id:crypto.randomUUID(),login:player.name,type,quantity};for(const client of hosts)sendEvent(client,'trade',trade);return json(res,202,{ok:true,id:trade.id,message:'Сделка отправлена в игру.'})
  }
  if(req.method==='POST'&&pathname==='/api/trade-result'){
    if(!isHost(req))return json(res,403,{error:'Недостаточно прав.'});let data;try{data=await readJson(req)}catch(error){return json(res,400,{error:error.message})}const login=typeof data.login==='string'?data.login.trim().toLowerCase():'';for(const client of clients)if(client.role==='viewer'&&client.login===login)sendEvent(client,'trade-result',{ok:Boolean(data.ok),message:String(data.message||'Сделка обработана.')});return json(res,200,{ok:true})
  }
  if(req.method==='GET')return serveFile(pathname,res);
  return json(res,405,{error:'Method not allowed'});
}).listen(Number(process.env.PORT)||3001,process.env.HOST||(process.env.PORT?'0.0.0.0':'127.0.0.1'),()=>console.log(`DROP IN открыт: http://localhost:${Number(process.env.PORT)||3001}`));

setInterval(()=>{for(const client of clients)if(!client.res.destroyed)client.res.write(': keep-alive\n\n')},20000).unref();
