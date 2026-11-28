const express=require('express'),http=require('http'),{WebSocketServer}=require('ws'),{createClient}=require('@libsql/client'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken');
const SECRET=process.env.JWT_SECRET||require('crypto').randomBytes(32).toString('hex'),PORT=process.env.PORT||3000;
// Kalıcı veritabanı: TURSO_DATABASE_URL verilirse bulutta (silinmez), yoksa yerel dosya
const db=createClient(process.env.TURSO_DATABASE_URL?{url:process.env.TURSO_DATABASE_URL,authToken:process.env.TURSO_AUTH_TOKEN}:{url:'file:'+(process.env.DB||'emrchat.db')});
const all=async(s,...a)=>{const r=await db.execute({sql:s,args:a});return r.rows.map(row=>Object.fromEntries(r.columns.map((c,i)=>[c,row[i]])))};
const q=async(s,...a)=>(await all(s,...a))[0],run=(s,...a)=>db.execute({sql:s,args:a});
const VERSION='3.0',path=require('path');
const init=async()=>{
  await run('CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,hash TEXT NOT NULL,ts INTEGER)');
  await run('CREATE TABLE IF NOT EXISTS friends(a TEXT,b TEXT,st TEXT,PRIMARY KEY(a,b))');
  await run('CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY AUTOINCREMENT,fr TEXT,too TEXT,text TEXT,img TEXT,ts INTEGER,rd INTEGER DEFAULT 0)');
  await run('CREATE INDEX IF NOT EXISTS mi ON msgs(fr,too)');
  for(const c of['avatar','tag','color','frame','badge','vip','nick','ban'])try{await run(`ALTER TABLE users ADD COLUMN ${c} TEXT`)}catch{}
  try{await run('ALTER TABLE msgs ADD COLUMN aud TEXT')}catch{}
  await run('CREATE TABLE IF NOT EXISTS grp(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,owner TEXT,pub INTEGER,ts INTEGER)');
  await run('CREATE TABLE IF NOT EXISTS gm(gid INTEGER,name TEXT,PRIMARY KEY(gid,name))');
  await run('CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,fr TEXT,target TEXT,reason TEXT,ts INTEGER)');
};
let ready0=null,dbError='';
const dbReady=()=>ready0||(ready0=init().then(()=>{dbError=''},e=>{ready0=null;dbError=String(e.message).slice(0,150);console.error('DB hatası:',e.message);throw e}));
dbReady().catch(()=>{});
const OWNERS={emre15456382:process.env.OWNER_PASSWORD,eren1545_0:process.env.OWNER2_PASSWORD},isOwner=n=>Object.hasOwn(OWNERS,n),RES=['DEV','MOD','ADM','STAF'],SPECIAL=['VIP','PRO','OG','STAR'];
const COL=['','#ef4444','#f59e0b','#22c55e','#06b6d4','#a855f7','#ec4899','rainbow'],FRM=['','blue','green','neon','gold'],BDG=['','🔥','⭐','🎮','💎','🚀','👑'];
const canVip=async n=>isOwner(n)||(await q('SELECT vip FROM users WHERE name=?',n))?.vip==='1';
const prof=async n=>{const p=(await q('SELECT avatar,tag,color,frame,badge,nick FROM users WHERE name=?',n))||{};if(isOwner(n))p.tag='DEV';return p};
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'10kb'}));app.get('/',(_,res)=>{res.set('Cache-Control','no-store');res.sendFile(path.join(__dirname,'index.html'))});
const hits=new Map(),NAME=/^[a-z0-9_]{3,16}$/;
const limited=ip=>{const n=Date.now(),h=(hits.get(ip)||[]).filter(t=>n-t<60000);h.push(n);hits.set(ip,h);return h.length>10};
const auth=reg=>async(req,res)=>{try{await dbReady();
  if(limited(req.ip))return res.status(429).json({e:'Çok fazla deneme, biraz bekle.'});
  const n=String(req.body.name||'').trim().toLowerCase(),p=String(req.body.pass||'');
  if(!NAME.test(n)||p.length<6||p.length>72)return res.status(400).json({e:'Kullanıcı adı 3-16 karakter (a-z 0-9 _), şifre en az 6 karakter.'});
  if(reg&&isOwner(n)&&(!OWNERS[n]||p!==OWNERS[n]))return res.status(403).json({e:'Bu kullanıcı adı ayrılmış.'});
  if(reg){try{await run('INSERT INTO users(name,hash,ts) VALUES(?,?,?)',n,bcrypt.hashSync(p,10),Date.now())}catch(e){if(/UNIQUE|constraint/i.test(e.message))return res.status(409).json({e:'Bu kullanıcı adı alınmış.'});throw e}}
  else{const u=await q('SELECT hash,ban FROM users WHERE name=?',n);if(!u||!bcrypt.compareSync(p,u.hash))return res.status(401).json({e:'Kullanıcı adı veya şifre yanlış.'});if(u.ban==='1')return res.status(403).json({e:'Hesabın yasaklandı.'})}
  res.json({token:jwt.sign({n},SECRET,{expiresIn:'30d'})})}catch(e){console.error(e);res.status(500).json({e:'Sunucu hatası, biraz sonra tekrar dene.'})}};
const who=async req=>{try{const n=jwt.verify((req.headers.authorization||'').slice(7),SECRET).n;return(await q('SELECT 1 x FROM users WHERE name=?',n))?n:null}catch{return null}};
const chk=async(req,res)=>{if(limited(req.ip)){res.status(429).json({e:'Çok fazla deneme.'});return null}const n=await who(req);if(!n){res.status(401).json({e:'Giriş gerekli.'});return null}
  const u=await q('SELECT hash FROM users WHERE name=?',n);if(!bcrypt.compareSync(String(req.body.op||''),u.hash)){res.status(401).json({e:'Şifre yanlış.'});return null}return n};
app.post('/api/password',async(req,res)=>{try{const n=await chk(req,res);if(!n)return;const np=String(req.body.np||'');if(np.length<6||np.length>72)return res.status(400).json({e:'Yeni şifre en az 6 karakter.'});
  await run('UPDATE users SET hash=? WHERE name=?',bcrypt.hashSync(np,10),n);res.json({ok:1})}catch(e){console.error(e);res.status(500).json({e:'Sunucu hatası.'})}});
app.post('/api/delete',async(req,res)=>{try{const n=await chk(req,res);if(!n)return;const fl=await friendsOf(n);
  for(const g of await all('SELECT id FROM grp WHERE owner=?',n)){await run('DELETE FROM msgs WHERE too=?','#'+g.id);await run('DELETE FROM gm WHERE gid=?',g.id);await run('DELETE FROM grp WHERE id=?',g.id)}
  for(const [x,a] of [['DELETE FROM msgs WHERE fr=? OR too=?',[n,n]],['DELETE FROM friends WHERE a=? OR b=?',[n,n]],['DELETE FROM gm WHERE name=?',[n]],['DELETE FROM reports WHERE fr=? OR target=?',[n,n]],['DELETE FROM users WHERE name=?',[n]]])await run(x,...a);
  on.get(n)?.forEach(w=>w.close(4001));fl.forEach(f=>push(f));res.json({ok:1})}catch(e){console.error(e);res.status(500).json({e:'Sunucu hatası.'})}});
app.get('/api/status',async(_,res)=>{let ok=false,users=0;try{await dbReady();users=Number((await q('SELECT COUNT(*) c FROM users')).c);ok=true}catch{}
  res.json({version:VERSION,db:process.env.TURSO_DATABASE_URL?'bulut':'yerel',ok,users,error:ok?'':dbError,founders:Object.values(OWNERS).map(Boolean)})});
app.get('/healthz',(_,res)=>res.send('ok'));
app.post('/api/register',auth(true));app.post('/api/login',auth(false));
app.get('/api/ice',async(_,res)=>{const s=[{urls:'stun:stun.l.google.com:19302'}];
  if(process.env.TURN_URL)s.push({urls:process.env.TURN_URL.split(',').map(x=>x.trim()),username:process.env.TURN_USER,credential:process.env.TURN_PASS});
  if(process.env.CF_TURN_KEY_ID&&process.env.CF_TURN_TOKEN)try{
    const r=await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${process.env.CF_TURN_KEY_ID}/credentials/generate-ice-servers`,{method:'POST',headers:{Authorization:'Bearer '+process.env.CF_TURN_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({ttl:86400})});
    const j=await r.json();[].concat(j.iceServers||[]).forEach(x=>s.push(x))}catch{}
  if(process.env.METERED_APP&&process.env.METERED_KEY)try{const r=await fetch(`https://${process.env.METERED_APP}.metered.live/api/v1/turn/credentials?apiKey=${process.env.METERED_KEY}`);[].concat(await r.json()).forEach(x=>x&&x.urls&&s.push(x))}catch{}
  res.json(s)});
const server=http.createServer(app),wss=new WebSocketServer({server,path:'/ws',maxPayload:1_500_000}),on=new Map();
const J=o=>JSON.stringify(o),send=(n,o)=>on.get(n)?.forEach(w=>w.readyState===1&&w.send(J(o)));
const friendsOf=async n=>(await all("SELECT CASE WHEN a=? THEN b ELSE a END f FROM friends WHERE st='ok' AND (a=? OR b=?)",n,n,n)).map(r=>r.f);
const areFriends=async(a,b)=>!!(await q("SELECT 1 x FROM friends WHERE st='ok' AND ((a=? AND b=?) OR (a=? AND b=?))",a,b,b,a));
const state=async n=>({t:'init',me:n,mp:await prof(n),ow:await canVip(n),owner:isOwner(n),
  friends:await Promise.all((await friendsOf(n)).map(async f=>({name:f,p:await prof(f),online:on.has(f),unread:Number((await q('SELECT COUNT(*) c FROM msgs WHERE fr=? AND too=? AND rd=0',f,n)).c)}))),
  reqs:await Promise.all((await all("SELECT a FROM friends WHERE b=? AND st='wait'",n)).map(async r=>({name:r.a,p:await prof(r.a)}))),sent:(await all("SELECT b FROM friends WHERE a=? AND st='wait'",n)).map(r=>r.b),
  groups:(await all('SELECT g.id,g.name,g.owner,(SELECT COUNT(*) FROM gm WHERE gid=g.id) c FROM grp g JOIN gm ON gm.gid=g.id WHERE gm.name=?',n)).map(g=>({...g,c:Number(g.c),id:Number(g.id)})),
  reports:isOwner(n)?await all('SELECT id,fr,target,reason FROM reports ORDER BY id DESC LIMIT 50'):[]});
const members=async gid=>(await all('SELECT name FROM gm WHERE gid=?',gid)).map(r=>r.name);
const owners=()=>Object.keys(OWNERS);
const push=async u=>{if(on.has(u))send(u,await state(u))};
const pres=async(n,o)=>(await friendsOf(n)).forEach(f=>send(f,{t:'presence',name:n,online:o}));
wss.on('connection',(ws,req)=>{
  let n;try{n=jwt.verify(new URL(req.url,'http://x').searchParams.get('token'),SECRET).n}catch{return ws.close(4001)}
  const ready=(async()=>{await dbReady();
    const u0=await q('SELECT ban FROM users WHERE name=?',n);if(!u0||u0.ban==='1'){ws.close(u0?4002:4001);return false}
    if(ws.readyState!==1)return false;
    const first=!on.has(n);if(first)on.set(n,new Set());on.get(n).add(ws);if(first)pres(n,true);
    ws.send(J(await state(n)));return true})().catch(e=>{console.error(e);return false});
  ws.on('message',async raw=>{try{if(!await ready)return;let m;try{m=JSON.parse(raw)}catch{return}
    const to=String(m.to||'').toLowerCase(),err=e=>ws.send(J({t:'err',e})),info=e=>ws.send(J({t:'info',e}));
    switch(m.t){
    case 'add':
      if(to===n||!(await q('SELECT 1 x FROM users WHERE name=?',to)))return err('Kullanıcı bulunamadı.');
      if(await q('SELECT 1 x FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)',n,to,to,n))return err('Zaten istek var veya arkadaşsınız.');
      await run("INSERT INTO friends VALUES(?,?,'wait')",n,to);push(n);push(to);break;
    case 'resp':
      if(!(await q("SELECT 1 x FROM friends WHERE a=? AND b=? AND st='wait'",to,n)))return;
      if(m.ok)await run("UPDATE friends SET st='ok' WHERE a=? AND b=?",to,n);else await run('DELETE FROM friends WHERE a=? AND b=?',to,n);
      push(n);push(to);break;
    case 'unfriend':
      await run('DELETE FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)',n,to,to,n);push(n);push(to);break;
    case 'profile':{const p=m.p||{},ok=(v,a)=>a.includes(v||''),tag=String(p.tag||'').toUpperCase(),vip=await canVip(n),nick=String(p.nick||'').trim().slice(0,20);
      const av=typeof p.avatar==='string'&&(p.avatar===''||(p.avatar.startsWith('data:image/')&&p.avatar.length<60000))?p.avatar:null;
      if(av===null)return err('Fotoğraf geçersiz veya çok büyük.');
      if(!/^[A-Z0-9]{0,4}$/.test(tag))return err('Etiket en fazla 4 harf/rakam olmalı.');
      if(RES.includes(tag)&&!isOwner(n))return err('Bu etiketi sadece kurucular kullanabilir.');
      if(SPECIAL.includes(tag)&&!vip)return err('Bu özel etiket sadece kurucunun verdiği kişilere açık.');
      if(!ok(p.color,COL)||!ok(p.frame,FRM)||!ok(p.badge,BDG))return err('Geçersiz seçim.');
      if((p.frame==='gold'||p.badge==='👑')&&!vip)return err('Altın çerçeve ve 👑 rozet özeldir.');
      await run('UPDATE users SET avatar=?,tag=?,color=?,frame=?,badge=?,nick=? WHERE name=?',av,tag,p.color||'',p.frame||'',p.badge||'',nick,n);
      push(n);(await friendsOf(n)).forEach(f=>push(f));break}
    case 'grant':{
      if(!isOwner(n))return err('Bu yetki sadece kurucularda.');
      if(isOwner(to)||!(await q('SELECT 1 x FROM users WHERE name=?',to)))return err('Kullanıcı bulunamadı.');
      await run('UPDATE users SET vip=? WHERE name=?',m.on?'1':'',to);
      if(!m.on)await run("UPDATE users SET frame=CASE WHEN frame='gold' THEN '' ELSE frame END,badge=CASE WHEN badge='👑' THEN '' ELSE badge END,tag=CASE WHEN tag IN ('VIP','PRO','OG','STAR') THEN '' ELSE tag END WHERE name=?",to);
      push(to);(await friendsOf(to)).forEach(f=>push(f));info((m.on?'Özel kozmetik verildi: @':'Özel kozmetik alındı: @')+to);break}
    case 'ban':{
      if(!isOwner(n))return err('Bu yetki sadece kurucularda.');
      if(isOwner(to))return err('Kurucular banlanamaz.');if(!(await q('SELECT 1 x FROM users WHERE name=?',to)))return err('Kullanıcı bulunamadı.');
      await run('UPDATE users SET ban=? WHERE name=?',m.on?'1':'',to);
      if(m.on){await run('DELETE FROM reports WHERE target=?',to);on.get(to)?.forEach(w=>w.close(4002))}
      owners().forEach(push);info((m.on?'Banlandı: @':'Ban kaldırıldı: @')+to);break}
    case 'rclose':if(isOwner(n)){await run('DELETE FROM reports WHERE id=?',Number(m.id));owners().forEach(push)}break;
    case 'report':
      if(to===n||!(await q('SELECT 1 x FROM users WHERE name=?',to)))return err('Kullanıcı bulunamadı.');
      await run('INSERT INTO reports(fr,target,reason,ts) VALUES(?,?,?,?)',n,to,String(m.reason||'').slice(0,300),Date.now());owners().forEach(push);info('Şikayetin kurucuya iletildi.');break;
    case 'search':{const sq=String(m.q||'').trim().toLowerCase().replace(/%/g,'').slice(0,16);if(!sq)return;
      const us=await all("SELECT name FROM users WHERE name LIKE ? AND name!=? AND (ban IS NULL OR ban!='1') ORDER BY name LIMIT 10",sq+'%',n),fl=await friendsOf(n);
      const gs=await all('SELECT id,name FROM grp WHERE pub=1 AND name LIKE ? LIMIT 10','%'+sq+'%');
      ws.send(J({t:'results',users:await Promise.all(us.map(async u=>({name:u.name,p:await prof(u.name),friend:fl.includes(u.name)}))),groups:gs.map(g=>({id:Number(g.id),name:g.name}))}));break}
    case 'gcreate':{const name=String(m.name||'').trim().slice(0,24);if(name.length<2)return err('Grup adı en az 2 karakter.');
      const id=Number((await run('INSERT INTO grp(name,owner,pub,ts) VALUES(?,?,?,?)',name,n,m.pub?1:0,Date.now())).lastInsertRowid),fl=await friendsOf(n);
      const mem=new Set([n,...[].concat(m.members||[]).map(x=>String(x).toLowerCase()).filter(x=>fl.includes(x))]);
      for(const u of mem)await run('INSERT INTO gm VALUES(?,?)',id,u);mem.forEach(push);break}
    case 'gjoin':{const g=await q('SELECT id FROM grp WHERE id=? AND pub=1',Number(m.gid));if(!g)return err('Grup bulunamadı.');await run('INSERT OR IGNORE INTO gm VALUES(?,?)',g.id,n);push(n);break}
    case 'gleave':{const id=Number(m.gid);await run('DELETE FROM gm WHERE gid=? AND name=?',id,n);
      if(!(await members(id)).length){await run('DELETE FROM grp WHERE id=?',id);await run('DELETE FROM msgs WHERE too=?','#'+id)}push(n);break}
    case 'hist':{
      if(/^#\d+$/.test(m.to||'')){if(!(await members(Number(m.to.slice(1)))).includes(n))return;
        ws.send(J({t:'hist',with:m.to,msgs:(await all('SELECT id,fr,text,img,aud,ts,rd FROM msgs WHERE too=? ORDER BY id DESC LIMIT 100',m.to)).reverse()}));break}
      if(!(await areFriends(n,to)))return;await run('UPDATE msgs SET rd=1 WHERE fr=? AND too=?',to,n);
      ws.send(J({t:'hist',with:to,msgs:await all('SELECT id,fr,text,img,aud,ts,rd FROM (SELECT * FROM msgs WHERE (fr=? AND too=?) OR (fr=? AND too=?) ORDER BY id DESC LIMIT 100) ORDER BY id',n,to,to,n)}));
      send(to,{t:'read',by:n});break}
    case 'msg':{const g=/^#\d+$/.test(m.to||'');let dest;
      if(g){dest=await members(Number(m.to.slice(1)));if(!dest.includes(n))return}else{if(!(await areFriends(n,to)))return;dest=[to]}
      const text=String(m.text||'').slice(0,2000),img=typeof m.img==='string'&&m.img.startsWith('data:image/')&&m.img.length<1_000_000?m.img:null,
        aud=typeof m.aud==='string'&&m.aud.startsWith('data:audio/')&&m.aud.length<1_200_000?m.aud:null;
      if(!text&&!img&&!aud)return;const ts=Date.now(),key=g?m.to:to;
      const id=(await run('INSERT INTO msgs(fr,too,text,img,aud,ts) VALUES(?,?,?,?,?,?)',n,key,text,img,aud,ts)).lastInsertRowid;
      const o={t:'msg',id:Number(id),fr:n,to:key,text,img,aud,ts};new Set([n,...dest]).forEach(u=>send(u,o));break}
    case 'read':if(await areFriends(n,to)){await run('UPDATE msgs SET rd=1 WHERE fr=? AND too=?',to,n);send(to,{t:'read',by:n})}break;
    case 'typing':if(await areFriends(n,to))send(to,{t:'typing',from:n});break;
    case 'sig':if(await areFriends(n,to)&&m.kind&&J(m.data||{}).length<20000)send(to,{t:'sig',from:n,kind:m.kind,data:m.data});break;
    }}catch(e){console.error(e);try{ws.send(J({t:'err',e:'Sunucu hatası: '+String(e.message).slice(0,120)}))}catch{}}});
  ws.on('close',()=>{const s=on.get(n);if(!s)return;s.delete(ws);if(!s.size){on.delete(n);pres(n,false)}});
});
server.listen(PORT,()=>console.log('EmrChat v'+VERSION+' http://localhost:'+PORT+(process.env.TURSO_DATABASE_URL?' (bulut veritabanı)':' (yerel veritabanı)')));
