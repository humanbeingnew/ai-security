import { DurableObject } from "cloudflare:workers";
import { analyze, campaignId, clamp } from "./engine.js";

function json(x,status=200,extra={}){
  return new Response(JSON.stringify(x),{status,headers:{"content-type":"application/json;charset=utf-8","cache-control":"no-store",...extra}});
}
function clientIP(r){return r.headers.get("CF-Connecting-IP")||r.headers.get("X-Forwarded-For")?.split(",")[0]?.trim()||"unknown";}
function safeEqual(a,b){
  if(!a||!b||a.length!==b.length)return false;
  let x=0; for(let i=0;i<a.length;i++) x|=a.charCodeAt(i)^b.charCodeAt(i); return x===0;
}
function bearer(request){const v=request.headers.get("Authorization")||"";return v.startsWith("Bearer ")?v.slice(7):"";}
function isAdmin(request,env){return !!env.ADMIN_TOKEN && safeEqual(bearer(request),String(env.ADMIN_TOKEN));}
function requireAdmin(request,env){return isAdmin(request,env)?null:json({error:"admin authentication required"},401,{"www-authenticate":"Bearer"});}
function securityHeaders(h=new Headers()){
  h.set("x-content-type-options","nosniff"); h.set("x-frame-options","DENY"); h.set("referrer-policy","no-referrer"); h.set("permissions-policy","camera=(),microphone=(),geolocation=()");
  return h;
}
async function dbExec(env,sql,args=[]){if(!env.DB)return null;try{return await env.DB.prepare(sql).bind(...args).run();}catch{return null;}}
async function dbFirst(env,sql,args=[]){if(!env.DB)return null;try{return await env.DB.prepare(sql).bind(...args).first();}catch{return null;}}
async function dbAll(env,sql,args=[]){if(!env.DB)return {results:[]};try{return await env.DB.prepare(sql).bind(...args).all();}catch{return {results:[]};}}
async function isAllowed(env,ip){return !!(await dbFirst(env,"SELECT ip FROM allowlist WHERE ip=?",[ip]));}
async function isBlocklisted(env,ip){return !!(await dbFirst(env,"SELECT ip FROM blocklist WHERE ip=?",[ip]));}
async function activeBan(env,ip){
  const x=await dbFirst(env,"SELECT expires_at FROM bans WHERE ip=?",[ip]); if(!x)return false;
  if(Number(x.expires_at)>Date.now())return true; await dbExec(env,"DELETE FROM bans WHERE ip=?",[ip]); return false;
}
async function ban(env,ip,minutes,reason,score,strikes=1){
  const now=Date.now(), expires=now+minutes*60000;
  await dbExec(env,"INSERT INTO bans(ip,created_at,expires_at,reason,score,strikes) VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET expires_at=excluded.expires_at,reason=excluded.reason,score=MAX(bans.score,excluded.score),strikes=MAX(bans.strikes,excluded.strikes)",[ip,now,expires,reason,score,strikes]);
}
async function strikeCount(env,ip){const x=await dbFirst(env,"SELECT strikes FROM attackers WHERE ip=?",[ip]);return Number(x?.strikes||0);}
async function updateAttacker(env,e){
  const old=await dbFirst(env,"SELECT strikes FROM attackers WHERE ip=?",[e.ip]);
  const strikes=Number(old?.strikes||0)+(e.action==="BLOCK"?1:0);
  await dbExec(env,`INSERT INTO attackers(ip,first_seen,last_seen,requests,blocked,reviewed,max_risk,countries,threats,strikes) VALUES(?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen,requests=attackers.requests+1,blocked=attackers.blocked+excluded.blocked,reviewed=attackers.reviewed+excluded.reviewed,max_risk=MAX(attackers.max_risk,excluded.max_risk),countries=excluded.countries,threats=excluded.threats,strikes=MAX(attackers.strikes,excluded.strikes)`,
    [e.ip,e.ts,e.ts,1,e.action==="BLOCK"?1:0,e.action==="REVIEW"?1:0,e.risk,e.country,e.threat||"",strikes]);
  return strikes;
}
async function upsertIncident(env,e){
  if(!e.campaign_id)return;
  await dbExec(env,`INSERT INTO incidents(campaign_id,created_at,last_seen,ip,threat,risk,status,event_count) VALUES(?,?,?,?,?,?,?,1)
    ON CONFLICT(campaign_id) DO UPDATE SET last_seen=excluded.last_seen,risk=MAX(incidents.risk,excluded.risk),event_count=incidents.event_count+1,threat=excluded.threat`,
    [e.campaign_id,e.ts,e.ts,e.ip,e.threat,e.risk,e.action==="BLOCK"?"open":"observed"]);
}
async function broadcast(env,payload){
  try{
    const id=env.SOC.idFromName("global");
    await env.SOC.get(id).fetch(new Request("https://soc.internal/broadcast",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(payload)}));
  }catch{}
}
async function event(env,e){
  await dbExec(env,"INSERT INTO events(ts,ip,method,path,country,ua,risk,action,threat,reason,ai,latency_ms,campaign_id,request_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",[e.ts,e.ip,e.method,e.path,e.country,e.ua,e.risk,e.action,e.threat,e.reason,e.ai,e.latency,e.campaign_id,e.request_id]);
  await updateAttacker(env,e); await upsertIncident(env,e); await broadcast(env,e);
}
async function aiExplain(env,input,base){
  if(!env.AI || env.AI_ENABLED!=="true" || !base.hits.length || base.risk<55)return null;
  try{
    const out=await env.AI.run("@cf/zai-org/glm-4.7-flash",{messages:[
      {role:"system",content:"You are a defensive web security analyst. Never provide exploit instructions. Return concise JSON with classification, confidence, explanation, recommendation."},
      {role:"user",content:`Defensive WAF alert. Threats:${JSON.stringify(base.hits)} Method:${input.method} URL:${String(input.url).slice(0,300)} Body:${String(input.body||"").slice(0,1000)}`}
    ],max_tokens:220});
    return String(out?.response||out?.result||"").slice(0,1800);
  }catch{return null;}
}

// Lightweight isolate-local burst limiter. It is intentionally only a first layer; use the optional
// Cloudflare Rate Limiting binding for stronger distributed enforcement.
const buckets=new Map();
function localRate(env,key){
  const now=Date.now(), windowMs=Math.max(10000,Number(env.LOCAL_RATE_WINDOW_MS)||60000), limit=Math.max(10,Number(env.LOCAL_RATE_LIMIT)||60);
  let b=buckets.get(key); if(!b||now-b.start>=windowMs)b={start:now,count:0}; b.count++; buckets.set(key,b);
  if(buckets.size>5000){for(const [k,v] of buckets){if(now-v.start>=windowMs)buckets.delete(k);}}
  return {allowed:b.count<=limit,count:b.count,limit,resetAt:b.start+windowMs};
}
async function optionalRate(env,key){
  try{if(env.SENTINEL_RL)return await env.SENTINEL_RL.limit({key});}catch{}
  return null;
}

export class SOCStream extends DurableObject{
  constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;this.ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping","pong"));}
  async fetch(request){
    const url=new URL(request.url);
    if(url.pathname==="/broadcast"&&request.method==="POST"){
      const msg=await request.text();
      for(const ws of this.ctx.getWebSockets()){try{ws.send(msg);}catch{}}
      return new Response("ok");
    }
    if(request.headers.get("Upgrade")!=="websocket")return new Response("websocket required",{status:426});
    const protocol=request.headers.get("Sec-WebSocket-Protocol")||"";
    const parts=protocol.split(",").map(x=>x.trim());
    const token=parts[0]==="sentinel-v1"?parts[1]:"";
    if(!this.env?.ADMIN_TOKEN && !token)return new Response("admin token required",{status:401});
    if(this.env?.ADMIN_TOKEN && !safeEqual(token,String(this.env.ADMIN_TOKEN)))return new Response("unauthorized",{status:401});
    const pair=new WebSocketPair(); const [client,server]=Object.values(pair); this.ctx.acceptWebSocket(server); return new Response(null,{status:101,webSocket:client,headers:{"Sec-WebSocket-Protocol":"sentinel-v1"}});
  }
  webSocketMessage(ws,message){if(String(message)==="ping")try{ws.send("pong")}catch{}}
  webSocketClose(ws){try{ws.close()}catch{}}
  webSocketError(ws){try{ws.close()}catch{}}
}

export default {
 async fetch(request,env,ctx){
  const u=new URL(request.url), start=Date.now(), ip=clientIP(request), requestId=crypto.randomUUID();
  const path=u.pathname;
  if(path==="/api/health")return json({ok:true,service:"Sentinel AI WAF M5",time:new Date().toISOString(),d1:!!env.DB,ai:!!env.AI,adminConfigured:!!env.ADMIN_TOKEN});
  if(path==="/api/login"&&request.method==="POST"){
    const body=await request.json().catch(()=>({}));
    if(!env.ADMIN_TOKEN)return json({ok:false,error:"ADMIN_TOKEN is not configured"},503);
    return safeEqual(String(body.token||""),String(env.ADMIN_TOKEN))?json({ok:true}):json({ok:false,error:"invalid token"},401);
  }
  if(path.startsWith("/api/")&&path!=="/api/health"&&path!=="/api/login"){
    const denied=requireAdmin(request,env); if(denied)return denied;
  }
  if(path==="/api/events"&&request.method==="GET"){
    const limit=Math.min(200,Math.max(1,Number(u.searchParams.get("limit"))||40)); const r=await dbAll(env,"SELECT * FROM events ORDER BY id DESC LIMIT ?",[limit]); return json({events:r.results||[]});
  }
  if(path==="/api/stats"&&request.method==="GET"){
    const r=await dbFirst(env,"SELECT COUNT(*) requests,COALESCE(SUM(action='BLOCK'),0) blocked,COALESCE(SUM(action='REVIEW'),0) review,COALESCE(SUM(risk>=85),0) critical FROM events WHERE ts>?",[Date.now()-86400000]);
    const top=await dbAll(env,"SELECT ip,requests,blocked,max_risk,strikes,last_seen FROM attackers ORDER BY max_risk DESC,blocked DESC,last_seen DESC LIMIT 10");
    return json({...r,attackers:top.results||[]});
  }
  if(path==="/api/bans"&&request.method==="GET")return json({bans:(await dbAll(env,"SELECT * FROM bans WHERE expires_at>? ORDER BY expires_at DESC",[Date.now()])).results||[]});
  if(path==="/api/attackers"&&request.method==="GET")return json({attackers:(await dbAll(env,"SELECT * FROM attackers ORDER BY max_risk DESC,blocked DESC,last_seen DESC LIMIT 50")).results||[]});
  if(path==="/api/incidents"&&request.method==="GET")return json({incidents:(await dbAll(env,"SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 50")).results||[]});
  if(path==="/api/ban"&&request.method==="POST"){
    const b=await request.json().catch(()=>({})); if(!b.ip)return json({error:"ip required"},400); await ban(env,b.ip,Math.min(10080,Math.max(1,Number(b.minutes)||60)),b.reason||"manual",100,Number(b.strikes)||1); return json({ok:true});
  }
  if(path==="/api/unban"&&request.method==="POST"){const b=await request.json().catch(()=>({}));await dbExec(env,"DELETE FROM bans WHERE ip=?",[b.ip]);return json({ok:true});}
  if(path==="/api/allow"&&request.method==="POST"){const b=await request.json().catch(()=>({}));if(!b.ip)return json({error:"ip required"},400);await dbExec(env,"INSERT OR IGNORE INTO allowlist(ip,created_at) VALUES(?,?)",[b.ip,Date.now()]);await dbExec(env,"DELETE FROM bans WHERE ip=?",[b.ip]);return json({ok:true});}
  if(path==="/api/block"&&request.method==="POST"){const b=await request.json().catch(()=>({}));if(!b.ip)return json({error:"ip required"},400);await dbExec(env,"INSERT OR REPLACE INTO blocklist(ip,created_at,reason) VALUES(?,?,?)",[b.ip,Date.now(),b.reason||"manual"]);await ban(env,b.ip,10080,b.reason||"manual block",100,5);return json({ok:true});}
  if(path==="/api/inspect"&&request.method==="POST"){
    const input=await request.json().catch(()=>({})); const base=analyze(input); const ai=await aiExplain(env,input,base); return json({...base,ai});
  }
  if(path==="/ws"){
    if(!isAdmin(request,env)){
      const proto=(request.headers.get("Sec-WebSocket-Protocol")||"").split(",").map(x=>x.trim());
      if(proto[0]!=="sentinel-v1"||!safeEqual(proto[1]||"",String(env.ADMIN_TOKEN||"")))return new Response("unauthorized",{status:401});
    }
    const id=env.SOC.idFromName("global"); return env.SOC.get(id).fetch(request);
  }
  if(path.startsWith("/api/"))return json({error:"not found"},404);
  if(path==="/"||path.startsWith("/soc"))return env.ASSETS.fetch(request);

  if(await isAllowed(env,ip))return proxy(request,env,ctx,ip,{risk:0,hits:[],action:"ALLOW"});
  if(await isBlocklisted(env,ip)||await activeBan(env,ip))return new Response("Blocked by Sentinel AI WAF",{status:403,headers:securityHeaders(new Headers({"content-type":"text/plain;charset=utf-8","x-sentinel-action":"BLOCK","x-sentinel-reason":"active-ban"}))});

  const burst=localRate(`${ip}:${path.split("?")[0]}`); const rl=await optionalRate(env,ip);
  if(!burst.allowed || rl?.success===false){
    const ev={ts:Date.now(),ip,method:request.method,path,country:request.cf?.country||"--",ua:request.headers.get("user-agent")||"",risk:72,action:"REVIEW",threat:"Rate Limit",reason:"request burst exceeded",ai:null,latency:Date.now()-start,campaign_id:campaignId({ip,path,hits:[{type:"Rate Limit"}]}),request_id:requestId};
    ctx.waitUntil(event(env,ev));
    return new Response(JSON.stringify({error:"Rate limit exceeded",retry_after:Math.ceil((burst.resetAt-Date.now())/1000)}),{status:429,headers:securityHeaders(new Headers({"content-type":"application/json","retry-after":String(Math.max(1,Math.ceil((burst.resetAt-Date.now())/1000))),"x-sentinel-action":"REVIEW"}))});
  }

  const input={url:u.toString(),method:request.method,body:"",headers:request.headers};
  if(request.method!=="GET"&&request.method!=="HEAD"){try{input.body=await request.clone().text();}catch{}}
  const base=analyze(input); const ai=await aiExplain(env,input,base); const cmp=campaignId({ip,path,hits:base.hits});
  let strikes=await strikeCount(env,ip);
  if(base.action==="BLOCK"){
    strikes+=1;
    const threshold=Math.max(1,Number(env.BAN_ESCALATION_THRESHOLD)||3);
    const minutes=strikes>=threshold?Math.min(10080,(Number(env.AUTO_BAN_MINUTES)||60)*2):Number(env.AUTO_BAN_MINUTES)||60;
    await ban(env,ip,minutes,base.hits[0]?.type||"threat",base.risk,strikes);
  }
  const ev={ts:Date.now(),ip,method:request.method,path,country:request.cf?.country||"--",ua:request.headers.get("user-agent")||"",risk:base.risk,action:base.action,threat:base.hits.map(x=>x.type).join(", ")||null,reason:base.hits.length?"Rule match":"No known threat",ai,latency:Date.now()-start,campaign_id:cmp,request_id:requestId};
  ctx.waitUntil(event(env,ev));
  if(base.action==="BLOCK")return new Response(JSON.stringify({error:"Blocked by Sentinel AI WAF",risk:base.risk,threat:base.hits.map(x=>x.type),campaign_id:cmp}),{status:403,headers:securityHeaders(new Headers({"content-type":"application/json","x-sentinel-action":"BLOCK","x-sentinel-campaign":cmp}))});
  return proxy(request,env,ctx,ip,base);
 }
};

async function proxy(request,env,ctx,ip,base){
  const origin=String(env.PROTECTED_ORIGIN||"").replace(/\/$/,"");
  if(!origin||origin.includes("example.com"))return json({error:"PROTECTED_ORIGIN is not configured. Set it in wrangler.toml before protecting traffic."},503);
  const target=new URL(request.url), o=new URL(origin); o.pathname=target.pathname;o.search=target.search;
  const h=new Headers(request.headers); h.set("x-sentinel-risk",String(base.risk)); h.set("x-sentinel-action",base.action); h.set("x-forwarded-for",ip); h.delete("host");
  return fetch(new Request(o.toString(),{method:request.method,headers:h,body:["GET","HEAD"].includes(request.method)?undefined:request.body,redirect:"manual"}));
}
