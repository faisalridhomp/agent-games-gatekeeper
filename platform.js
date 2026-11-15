// Platform client for agentgames.zkverify.io server actions.
// Pattern (proven by the parent's registration): POST to the page URL that defines
// the action, STRING body JSON.stringify([arg1, arg2, ...]), header
// Next-Action: <action-id>, session cookie from cookies.json.
// Action IDs (from the site's JS chunks):
//   addAgentAction       406c653ffdf23ce1306a90d56bab9777bd095b4999  ({name,events,repoUrl,endpoint}) -> {ok,name,secret,agentId}|{ok:false,error}
//   updateAgentEndpoint  60034c90cfac0d0a2c276e06558fcc69411ada008e  (agentId, endpointUrl) -> {ok}|{ok:false,error}
//   rotateAgentSecret    401d2a0d4da0b58a3ad2f76340f07faffe712d96f6  (agentId) -> {ok,secret}|{ok:false,error}
//   preflightAgent       4004a8c359b186f7c18dcf3670b6660e389580c550  (agentId) -> {ok,latencyMs}|{ok:false,kind,error,endpointUrl}
//   dispatchPracticeTask 707d5d13b222ee40259b2cb073a5454917e650836a  (agentId, event, options) -> {ok,sessionId,...}|{ok:false,error,hint,diagnostic}
//   updateAgentEvents    604b59051f0e536777817161d77a22f3988f276191
//   updateAgentRepo      6093da527217b3740348cbdd30541f20fd5850e0aa
// Responses are Next.js flight text; the return object is extracted tolerantly.
// Never log the HMAC secret.
'use strict';
const fs = require('fs');
const BASE = 'https://agentgames.zkverify.io';
const ACTIONS = {
  addAgentAction: ['406c653ffdf23ce1306a90d56bab9777bd095b4999', '/dashboard/agents'],
  updateAgentEndpoint: ['60034c90cfac0d0a2c276e06558fcc69411ada008e', '/dashboard/agents'],
  rotateAgentSecret: ['401d2a0d4da0b58a3ad2f76340f07faffe712d96f6', '/dashboard/agents'],
  preflightAgent: ['4004a8c359b186f7c18dcf3670b6660e389580c550', '/dashboard/agents'],
  dispatchPracticeTask: ['707d5d13b222ee40259b2cb073a5454917e650836a', '/dashboard/practice'],
};

function cookies() {
  return JSON.parse(fs.readFileSync(__dirname + '/cookies.json', 'utf8')).cookie;
}

// Extract the action's return object from a Next.js flight response.
// The flight text embeds the serialized return value; we scan for a JSON object
// containing "ok" and parse the largest plausible candidate.
function extractReturn(text) {
  if (!text) return null;
  // Unescape flight string escapes.
  const t = text.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  const candidates = [];
  let depth = 0, start = -1;
  for (let i = 0; i < t.length; i++) {
    if (t[i] === '{') { if (depth === 0) start = i; depth++; }
    else if (t[i] === '}') {
      depth--;
      if (depth === 0 && start >= 0) { candidates.push(t.slice(start, i + 1)); start = -1; }
    }
  }
  for (const c of candidates.reverse()) {
    try {
      const o = JSON.parse(c);
      if (o && typeof o === 'object' && 'ok' in o) return o;
    } catch (_) { /* not JSON, keep scanning */ }
  }
  return null;
}

async function callAction(name, args) {
  const [id, page] = ACTIONS[name];
  const r = await fetch(BASE + page, {
    method: 'POST',
    headers: {
      Cookie: cookies(),
      'User-Agent': 'Mozilla/5.0',
      'Next-Action': id,
      'Content-Type': 'text/plain;charset=UTF-8',
    },
    body: JSON.stringify(args),
  });
  const text = await r.text();
  const ret = extractReturn(text);
  return { httpStatus: r.status, ret, rawHead: text.slice(0, 800) };
}

module.exports = { callAction, ACTIONS };
if (require.main === module) {
  (async () => {
    const [name, ...rest] = process.argv.slice(2);
    const args = rest.map((a) => { try { return JSON.parse(a); } catch (_) { return a; } });
    const out = await callAction(name, args);
    // Redact any secret in the output before printing.
    const s = JSON.stringify(out, null, 2);
    console.log(out.ret && out.ret.secret ? s.replace(out.ret.secret, '<SECRET-REDACTED>') : s);
  })().catch((e) => { console.error('FAIL:', e.message); process.exit(1); });
}
