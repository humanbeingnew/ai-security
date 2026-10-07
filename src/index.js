import { DurableObject } from "cloudflare:workers";

const RULES = [
  ["SQL Injection", "critical", 96, [/\bunion\s+(?:all\s+)?select\b/i,/\bselect\s+.+\s+from\b/i,/(?:'|%27)\s*(?:or|and)\s+[^\s]+\s*=\s*[^\s]+/i,/\bdrop\s+table\b/i,/\b(?:sleep|benchmark)\s*\(/i]],
  ["XSS", "critical", 94, [/<\s*script\b/i,/javascript\s*:/i,/\bon(?:error|load|click|mouseover)\s*=/i,/document\.(?:cookie|location)/i]],
  ["Path Traversal", "high", 88, [/\.\.\//, /\.\.\\\\/, /%2e%2e%2f/i, /%2e%2e%5c/i]],
  ["Command Injection", "critical", 98, [/(?:^|[;&|])\s*(?:bash|sh|cmd|powershell|curl|wget|nc|cat)\b/i,/\$\([^)]*\)/,/`[^`]+`/]],
  ["Scanner", "medium", 70, [/\b(?:sqlmap|nmap|nikto|masscan|wpscan|gobuster|dirbuster)\b/i]],
  ["Sensitive Path", "high", 84, [/\/(?:\.env|\.git|wp-config\.php|server-status|actuator|phpinfo)\b/i]]
];

function clamp(n){return Math.max(0,Math.min(100,Number(n)||0));}
function clientIP(r){return r.headers.get("CF-Connecting-IP")||r.headers.get("X-Forwarded-For")?.split(",")[0]?.trim()||"unknown";}
function analyze({url,method,body,headers}){
  const ua=headers?.get?.("user-agent")||headers?.["user-agent"]||"";
  const hay=`${url}\n${method}\n${body||""}\n${ua}`;
  const hits=[];
  for(const [type,severity,score,patterns] of RULES){if(patterns.some(p=>p.test(hay))) hits.push({type,severity,score});}
  let risk=hits.length?Math.max(...hits.map(x=>x.score)):2;
  if(/\b(?:curl|python-requests|httpx)\b/i.test(ua)) risk=Math.max(risk,35);
  return {risk:clamp(risk),hits,action:risk>=85?"BLOCK":risk>=55?"REVIEW":"ALLOW"};
}
async function aiExplain(env, input, base){
  if(!env.AI || env.AI_ENABLED!=="true" || !base.hits.length || base.risk<55) return null;
  try{
    const out=await env.AI.run("@cf/zai-org/glm-4.7-flash",{messages:[
      {role:"system",content:"You are a defensive web security analyst. Never provide exploit instructions. Return concise JSON."},
      {role:"user",content:`Analyze this defensive WAF alert. Return JSON keys classification,confidence,explanation,recommendation.\nThreats:${JSON.stringify(base.hits)}\nMethod:${input.method}\nURL:${String(input.url).slice(0,300)}\nBody:${String(input.body||"").slice(0,1000)}`}
    ],max_tokens:220});
    return String(out?.response||out?.result||"").slice(0,1800);
  }catch{return null;}
}
async function dbExec(env,sql,args=[]){if(!env.DB)return; try{await env.DB.prepare(sql).bind(...args).run();}catch{} }
async function isAllowed(env,ip){if(!env.DB)return false; try{return !!(await env.DB.prepare("SELECT ip FROM allowlist WHERE ip=?").bind(ip).first());}catch{return false;}}
async function activeBan(env,ip){if(!env.DB)return false; try{const x=await env.DB.prepare("SELECT expires_at FROM bans WHERE ip=?").bind(ip).first(); if(!x)return false; if(x.expires_at>Date.now())return true; await dbExec(env,"DELETE FROM bans WHERE ip=?",[ip]); return false;}catch{return false;}}
async function ban(env,ip,minutes,reason,score){await dbExec(env,"INSERT OR REPLACE INTO bans(ip,created_at,expires_at,reason,score) VALUES(?,?,?,?,?)",[ip,Date.now(),Date.now()+minutes*60000,reason,score]);}
async function event(env,e){await dbExec(env,"INSERT INTO events(ts,ip,method,path,country,ua,risk,action,threat,reason,ai,latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",[Date.now(),e.ip,e.method,e.path,e.country,e.ua,e.risk,e.action,e.threat,e.reason,e.ai,e.latency]); try{const id=env.SOC.idFromName("global"); await env.SOC.get(id).broadcast(JSON.stringify(e));}catch{}}
function json(x,status=200){return new Response(JSON.stringify(x),{status,headers:{"content-type":"application/json;charset=utf-8","cache-control":"no-store"}});}

export class SOCStream extends DurableObject{
  constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.clients=new Set();}
  async fetch(req){if(req.headers.get("Upgrade")!=="websocket")return new Response("websocket required",{status:426});const pair=new WebSocketPair();this.ctx.acceptWebSocket(pair[1]);this.clients.add(pair[1]);return new Response(null,{status:101,webSocket:pair[0]});}
  webSocketClose(ws){this.clients.delete(ws);} webSocketError(ws){this.clients.delete(ws);}
  broadcast(msg){for(const ws of this.ctx.getWebSockets()){try{ws.send(msg);}catch{}}}
}

export default {
 async fetch(request,env,ctx){
  const u=new URL(request.url); const start=Date.now(); const ip=clientIP(request);
  if(u.pathname==="/api/health") return json({ok:true,service:"Sentinel AI WAF M4",time:new Date().toISOString()});
  if(u.pathname==="/api/events"&&request.method==="GET"){
    if(!env.DB)return json({events:[]});
    const limit=Math.min(100,Number(u.searchParams.get("limit"))||40); const r=await env.DB.prepare("SELECT * FROM events ORDER BY id DESC LIMIT ?").bind(limit).all(); return json({events:r.results||[]});
  }
  if(u.pathname==="/api/stats"&&request.method==="GET"){
    if(!env.DB)return json({requests:0,blocked:0,review:0,critical:0});
    const r=await env.DB.prepare("SELECT COUNT(*) requests, SUM(action='BLOCK') blocked, SUM(action='REVIEW') review, SUM(risk>=85) critical FROM events WHERE ts>? ").bind(Date.now()-86400000).first();
    return json(r||{});
  }
  if(u.pathname==="/api/bans"&&request.method==="GET") {if(!env.DB)return json({bans:[]});const r=await env.DB.prepare("SELECT * FROM bans WHERE expires_at>? ORDER BY expires_at DESC").bind(Date.now()).all();return json({bans:r.results||[]});}
  if(u.pathname==="/api/ban"&&request.method==="POST") {const b=await request.json();if(!b.ip)return json({error:"ip required"},400);await ban(env,b.ip,Math.min(10080,Number(b.minutes)||60),b.reason||"manual",100);return json({ok:true});}
  if(u.pathname==="/api/unban"&&request.method==="POST") {const b=await request.json();await dbExec(env,"DELETE FROM bans WHERE ip=?",[b.ip]);return json({ok:true});}
  if(u.pathname==="/api/allow"&&request.method==="POST") {const b=await request.json();await dbExec(env,"INSERT OR IGNORE INTO allowlist(ip,created_at) VALUES(?,?)",[b.ip,Date.now()]);return json({ok:true});}
  if(u.pathname==="/api/inspect"&&request.method==="POST") {const input=await request.json();const base=analyze(input);const ai=await aiExplain(env,input,base);return json({...base,ai});}
  if(u.pathname==="/ws") {const id=env.SOC.idFromName("global");return env.SOC.get(id).fetch(request);}

  if(u.pathname.startsWith("/api/"))return json({error:"not found"},404);
  if(u.pathname.startsWith("/soc")||u.pathname==="/")return env.ASSETS.fetch(request);

  if(await isAllowed(env,ip)) return proxy(request,env,ctx,start,ip,{risk:0,hits:[],action:"ALLOW"},"allowlist");
  if(await activeBan(env,ip)) return new Response("Blocked by Sentinel AI WAF",{status:403,headers:{"content-type":"text/plain;charset=utf-8","x-sentinel-action":"BLOCK","x-sentinel-reason":"active-ban"}});
  const input={url:u.toString(),method:request.method,body:"",headers:request.headers};
  let body=""; if(request.method!=="GET"&&request.method!=="HEAD"){try{body=await request.clone().text();}catch{}} input.body=body;
  const base=analyze(input); const ai=await aiExplain(env,input,base);
  if(base.action==="BLOCK") await ban(env,ip,Number(env.AUTO_BAN_MINUTES)||60,base.hits[0]?.type||"threat",base.risk);
  const ev={ip,method:request.method,path:u.pathname,country:request.cf?.country||"--",ua:request.headers.get("user-agent")||"",risk:base.risk,action:base.action,threat:base.hits.map(x=>x.type).join(", ")||null,reason:base.hits.length?"Rule match":"No known threat",ai,latency:Date.now()-start};
  ctx.waitUntil(event(env,ev));
  if(base.action==="BLOCK")return new Response(JSON.stringify({error:"Blocked by Sentinel AI WAF",risk:base.risk,threat:base.hits.map(x=>x.type)}),{status:403,headers:{"content-type":"application/json","x-sentinel-action":"BLOCK"}});
  return proxy(request,env,ctx,start,ip,base,ai);
 }
};
async function proxy(request,env,ctx,start,ip,base,ai){const origin=String(env.PROTECTED_ORIGIN||"").replace(/\/$/,"");if(!origin||origin.includes("example.com"))return env.ASSETS.fetch(request);const target=new URL(request.url);const o=new URL(origin);o.pathname=target.pathname;o.search=target.search;const h=new Headers(request.headers);h.set("x-sentinel-risk",String(base.risk));h.set("x-sentinel-action",base.action);h.set("x-forwarded-for",ip);const r=await fetch(new Request(o.toString(),{method:request.method,headers:h,body:["GET","HEAD"].includes(request.method)?undefined:request.body,redirect:"manual"}));return r;}
