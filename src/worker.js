// Bottaranza – API account e salvataggi (Cloudflare Workers + D1)
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const err=(m,s=400)=>J({error:m},s);
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
async function hash(pw,salt){
  const enc=new TextEncoder();
  const key=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);
  return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:100000,hash:'SHA-256'},key,256));
}
function same(a,b){if(a.length!==b.length)return false;let r=0;for(let i=0;i<a.length;i++)r|=a.charCodeAt(i)^b.charCodeAt(i);return r===0;}
const okEmail=e=>typeof e==='string'&&e.length<=120&&/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
async function body(req){try{return await req.json();}catch{return null;}}
async function who(req,env){
  const a=req.headers.get('authorization')||'';const t=a.startsWith('Bearer ')?a.slice(7):'';
  if(!/^[0-9a-f]{64}$/.test(t))return null;
  const r=await env.DB.prepare('SELECT email,created_at FROM sessions WHERE token=?').bind(t).first();
  if(r&&Date.now()-r.created_at>SESS_MAX){await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(t).run();return null;}
  return r?{email:r.email,token:t}:null;
}
const WIN=15*60*1000;
async function tooMany(env,keys,max){const since=Date.now()-WIN;for(const [k,n] of keys){const r=await env.DB.prepare('SELECT COUNT(*) c FROM attempts WHERE k=? AND at>?').bind(k,since).first();if(r&&r.c>=n)return true;}return false;}
async function fail(env,keys){const now=Date.now();await env.DB.batch(keys.map(([k])=>env.DB.prepare('INSERT INTO attempts(k,at) VALUES(?,?)').bind(k,now)));if(Math.random()<.05)await env.DB.prepare('DELETE FROM attempts WHERE at<?').bind(now-WIN).run();}
const SESS_MAX=90*24*3600*1000;
async function newSession(env,email){const t=rnd(32);await env.DB.prepare('INSERT INTO sessions(token,email,created_at) VALUES(?,?,?)').bind(t,email,Date.now()).run();return t;}

export default {
  async fetch(req,env){
    const url=new URL(req.url),p=url.pathname,m=req.method;
    if(!p.startsWith('/api/'))return env.ASSETS.fetch(req);
    if(m!=='GET'&&req.headers.get('content-type')?.includes('application/json')!==true&&m!=='DELETE')return err('Formato non valido.',415);
    try{
      const ip=req.headers.get('cf-connecting-ip')||'x',day=new Date().toISOString().slice(0,10);
      const bump=(k)=>env.DB.prepare('INSERT INTO stats(d,k,n) VALUES(?,?,1) ON CONFLICT(d,k) DO UPDATE SET n=n+1').bind(day,k).run();
      if(p==='/api/ev'&&m==='POST'){
        const b=await body(req);const k=b&&String(b.k||'');
        if(!/^(start|day5|day10|day30|bot_(maranza|insta|aura|gym|crypto|pet)|tut_done|tut_skip)$/.test(k))return err('Evento non valido.');
        if(await tooMany(env,[['ev:'+ip,300]]))return J({ok:false});
        await fail(env,[['ev:'+ip]]);await bump(k);return J({ok:true});
      }
      if(p==='/api/feedback'&&m==='POST'){
        const b=await body(req);if(!b)return err('Richiesta non valida.');
        const kind=['bug','idea','commento'].includes(b.kind)?b.kind:'commento';
        const msg=String(b.msg||'').trim().slice(0,2000);if(msg.length<3)return err('Scrivi almeno qualche parola.');
        const mail=String(b.mail||'').trim().slice(0,120);if(mail&&!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail))return err('Email non valida.');
        const since=Date.now()-3600*1000;const c=await env.DB.prepare('SELECT COUNT(*) c FROM attempts WHERE k=? AND at>?').bind('fb:'+ip,since).first();
        if(c&&c.c>=5)return err('Hai già mandato 5 messaggi in un\'ora. Riprova più tardi.',429);
        await env.DB.prepare('INSERT INTO attempts(k,at) VALUES(?,?)').bind('fb:'+ip,Date.now()).run();
        await env.DB.prepare('INSERT INTO feedback(at,kind,msg,mail,meta,done) VALUES(?,?,?,?,?,0)').bind(Date.now(),kind,msg,mail,JSON.stringify(b.meta||{}).slice(0,600)).run();
        await bump('fb_'+kind);return J({ok:true});
      }
      if(p.startsWith('/api/admin/')){
        if(!env.STATS_KEY||req.headers.get('x-key')!==env.STATS_KEY){await new Promise(r=>setTimeout(r,800));return err('Codice errato.',401);}
        if(p==='/api/admin/stats'&&m==='GET'){
          const st=await env.DB.prepare('SELECT d,k,n FROM stats WHERE d>=? ORDER BY d DESC').bind(new Date(Date.now()-90*864e5).toISOString().slice(0,10)).all();
          const fb=await env.DB.prepare('SELECT id,at,kind,msg,mail,meta,done FROM feedback ORDER BY done ASC, at DESC LIMIT 300').all();
          const us=await env.DB.prepare('SELECT COUNT(*) c FROM users').first();
          return J({stats:st.results,feedback:fb.results,users:us?us.c:0});
        }
        if(p==='/api/admin/fb'&&m==='POST'){const b=await body(req);if(!b)return err('Richiesta non valida.');
          if(b.del)await env.DB.prepare('DELETE FROM feedback WHERE id=?').bind(+b.id).run();
          else await env.DB.prepare('UPDATE feedback SET done=? WHERE id=?').bind(b.done?1:0,+b.id).run();return J({ok:true});}
        return err('Non trovato.',404);
      }
      if(p==='/api/register'&&m==='POST'){
        const b=await body(req);if(!b)return err('Richiesta non valida.');
        const email=String(b.email||'').trim().toLowerCase(),pw=String(b.pw||''),nick=String(b.nick||'').trim().slice(0,20);
        if(!okEmail(email))return err('Email non valida.');
        if(pw.length<8||pw.length>200)return err('La password deve avere almeno 8 caratteri.');
        if(!nick)return err('Serve un nickname.');
        if(!['minor','adult'].includes(b.age))return err('Fascia d\'età non valida.');
        const ipk=[['reg:'+(req.headers.get('cf-connecting-ip')||'x'),5]];
        if(await tooMany(env,ipk))return err('Troppi account creati da questa connessione. Riprova più tardi.',429);
        const ex=await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first();
        if(ex)return err('Esiste già un account con questa email.',409);
        const salt=rnd(16);
        await env.DB.prepare('INSERT INTO users(email,nick,salt,hash,age,terms_version,terms_at,created_at) VALUES(?,?,?,?,?,?,?,?)')
          .bind(email,nick,salt,await hash(pw,salt),b.age,String(b.tv||''),Date.now(),Date.now()).run();
        await fail(env,ipk);await bump('acct');
        return J({token:await newSession(env,email),email,nick});
      }
      if(p==='/api/login'&&m==='POST'){
        const b=await body(req);if(!b)return err('Richiesta non valida.');
        const email=String(b.email||'').trim().toLowerCase(),pw=String(b.pw||'');
        const keys=[['ip:'+(req.headers.get('cf-connecting-ip')||'x'),20],['em:'+email,8]];
        if(await tooMany(env,keys))return err('Troppi tentativi sbagliati. Riprova tra 15 minuti.',429);
        const u=await env.DB.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
        if(!u||!same(u.hash,await hash(pw,u.salt))){await fail(env,keys);return err('Email o password non corretti.',401);}
        return J({token:await newSession(env,email),email,nick:u.nick});
      }
      const me=await who(req,env);
      if(!me)return err('Sessione scaduta: accedi di nuovo.',401);
      if(p==='/api/logout'&&m==='POST'){await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(me.token).run();return J({ok:true});}
      if(p==='/api/save'&&m==='GET'){
        const s=await env.DB.prepare('SELECT at,data FROM saves WHERE email=?').bind(me.email).first();
        return J(s?{at:s.at,data:JSON.parse(s.data)}:{at:0,data:null});
      }
      if(p==='/api/save'&&m==='PUT'){
        const raw=await req.text();if(raw.length>400000)return err('Salvataggio troppo grande.',413);
        let b;try{b=JSON.parse(raw);}catch{return err('Richiesta non valida.');}
        const at=Number(b.at)||Date.now();
        await env.DB.prepare('INSERT INTO saves(email,at,data) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET at=excluded.at,data=excluded.data WHERE excluded.at>=saves.at')
          .bind(me.email,at,JSON.stringify(b.data??null)).run();
        return J({ok:true,at});
      }
      if(p==='/api/export'&&m==='GET'){
        const u=await env.DB.prepare('SELECT email,nick,age,terms_version,terms_at,created_at FROM users WHERE email=?').bind(me.email).first();
        const s=await env.DB.prepare('SELECT at,data FROM saves WHERE email=?').bind(me.email).first();
        return J({account:u,salvataggio:s?{at:s.at,data:JSON.parse(s.data)}:null});
      }
      if(p==='/api/account'&&m==='DELETE'){
        await env.DB.batch([
          env.DB.prepare('DELETE FROM saves WHERE email=?').bind(me.email),
          env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(me.email),
          env.DB.prepare('DELETE FROM users WHERE email=?').bind(me.email)]);
        return J({ok:true});
      }
      return err('Non trovato.',404);
    }catch(e){return err('Errore del server. Riprova tra poco.',500);}
  }
};
