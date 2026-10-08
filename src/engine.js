export const RULES = [
  ["SQL Injection", "critical", 96, [
    /\bunion\s+(?:all\s+)?select\b/i,
    /\bselect\s+.+\s+from\b/i,
    /(?:'|%27)\s*(?:or|and)\s+[^\s]+\s*=\s*[^\s]+/i,
    /\bdrop\s+table\b/i,
    /\b(?:sleep|benchmark)\s*\(/i
  ]],
  ["XSS", "critical", 94, [
    /<\s*script\b/i,
    /javascript\s*:/i,
    /\bon(?:error|load|click|mouseover|focus)\s*=/i,
    /document\.(?:cookie|location)/i
  ]],
  ["Path Traversal", "high", 88, [/\.\.\//, /\.\.\\\\/, /%2e%2e%2f/i, /%2e%2e%5c/i]],
  ["Command Injection", "critical", 98, [
    /(?:^|[;&|])\s*(?:bash|sh|cmd|powershell|curl|wget|nc|cat)\b/i,
    /\$\([^)]*\)/,
    /`[^`]+`/
  ]],
  ["Scanner", "medium", 70, [/\b(?:sqlmap|nmap|nikto|masscan|wpscan|gobuster|dirbuster)\b/i]],
  ["Sensitive Path", "high", 84, [/\/(?:\.env|\.git(?:\/|$)|wp-config\.php|server-status|actuator|phpinfo)\b/i]],
  ["Suspicious Encoding", "medium", 62, [/(?:%25){2,}/i, /%(?:[0-9a-f]{2}){8,}/i]]
];

export function clamp(n){return Math.max(0, Math.min(100, Number(n) || 0));}

export function analyze({url="", method="GET", body="", headers={}}={}){
  const getHeader = (k) => headers?.get?.(k) ?? headers?.[k] ?? headers?.[k.toLowerCase()] ?? "";
  const ua = getHeader("user-agent");
  const hay = `${url}\n${method}\n${body || ""}\n${ua}`;
  const hits=[];
  for(const [type,severity,score,patterns] of RULES){
    if(patterns.some(p => p.test(hay))) hits.push({type,severity,score});
  }
  let risk = hits.length ? Math.max(...hits.map(x=>x.score)) : 2;
  if(/\b(?:curl|python-requests|httpx)\b/i.test(ua)) risk=Math.max(risk,35);
  if(body && body.length > 50000) risk=Math.max(risk,25);
  if(hits.length >= 2) risk=Math.min(100, risk + 4);
  return {risk:clamp(risk), hits, action:risk>=85?"BLOCK":risk>=55?"REVIEW":"ALLOW"};
}

export function campaignId({ip="", path="", hits=[]}={}){
  const threat = hits.map(x=>x.type).sort().join("+") || "normal";
  const raw = `${ip}|${path.split("?")[0]}|${threat}`;
  let h = 2166136261;
  for(let i=0;i<raw.length;i++){h^=raw.charCodeAt(i);h=Math.imul(h,16777619);}
  return `cmp-${(h>>>0).toString(16).padStart(8,"0")}`;
}
