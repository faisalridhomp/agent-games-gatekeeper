// Proof Gatekeeper agent for zkVerify Agent Games (Season 01).
// Plain Node.js (no framework). Listens on 127.0.0.1:PORT, behind a cloudflared tunnel.
// Protocol (from https://agentgames.zkverify.io/build):
//  - POST task envelope {type:"agent-games.proof-gatekeeper.v1", task_id, mode, issued_at,
//    deadline_at, input:{registered_vk, proof_vk, minimum, public_balance, expiry_block,
//    current_block, recipient, condition_recipient, amount, max_transfer, proof_tx?}}
//    signed with HMAC-SHA256 over the RAW body -> x-agent-games-signature header.
//  - Decide APPROVE only if every check passes, else REJECT with reason_code
//    (VK_SUBSTITUTION / RECIPIENT_MISMATCH / THRESHOLD_MISMATCH).
//  - Generate a Groth16 proof locally with snarkjs (decision is enforced by the circuit).
//  - Respond {decision, reason_code, proof, public_signals, proof_tx?} signed with
//    x-agent-games-signature over the raw response body. 60s hard deadline; fail closed.
//  - Preflight (any signed non-task POST): respond {ok:true, protocolVersion:"v1"} signed.
// Secrets come from .env (mode 600). Never log secrets.
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DIR = __dirname;
const PORT = parseInt(process.env.PORT || '8787', 10);
const WASM = path.join(DIR, 'gatekeeper.wasm');
const ZKEY = path.join(DIR, 'gatekeeper_final.zkey');
const LOG = path.join(DIR, 'agent-requests.log');
const REGISTERED_VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---- config (.env, mode 600) ----
function loadEnv() {
  const out = {};
  try {
    for (const line of fs.readFileSync(path.join(DIR, '.env'), 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m) out[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch (_) { /* no .env yet */ }
  return out;
}
const ENV = loadEnv();
// Railway injects variables into process.env (no .env file); prefer the
// environment, fall back to .env for local runs.
let HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || ENV.AGENT_GAMES_HMAC_SECRET || '';
const KURIER_API_KEY = process.env.KURIER_API_KEY || ENV.KURIER_API_KEY || '';

const snarkjs = require(path.join(DIR, 'node_modules', 'snarkjs'));
const { ethers } = require('ethers');

function log(obj) {
  const line = JSON.stringify({ t: new Date().toISOString(), ...obj }) + '\n';
  fs.appendFileSync(LOG, line);
  console.log(line.trim());
}

function hmacHex(secret, bodyBuf) {
  return crypto.createHmac('sha256', secret).update(bodyBuf).digest('hex');
}
function signBody(secret, bodyStr) {
  return hmacHex(secret, Buffer.from(bodyStr, 'utf8'));
}
function verifySig(secret, bodyBuf, headerVal) {
  if (!secret || !headerVal) return false;
  let hv = String(headerVal).trim();
  if (hv.toLowerCase().startsWith('sha256=')) hv = hv.slice(7);
  const want = hmacHex(secret, bodyBuf);
  try {
    const a = Buffer.from(hv, 'hex'), b = Buffer.from(want, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (_) {
    return hv.toLowerCase() === want.toLowerCase();
  }
}

// keccak256(task_id) mod p -> circuit field element for taskId
function taskIdField(taskId) {
  const h = ethers.keccak256(ethers.toUtf8Bytes(String(taskId)));
  return (BigInt(h) % FIELD_P).toString();
}
// Deterministic salt bound to the task (platform cannot recompute a random salt;
// a task-bound salt is the only reproducible choice). Falls back cleanly.
function taskSalt(taskId) {
  const h = ethers.keccak256(ethers.toUtf8Bytes('agent-games-salt:' + String(taskId)));
  return (BigInt(h) % FIELD_P).toString();
}

function decide(input) {
  const regVk = String(input.registered_vk || '').toLowerCase();
  const proofVk = String(input.proof_vk || '').toLowerCase();
  const minimum = BigInt(String(input.minimum));
  const balance = BigInt(String(input.public_balance));
  const expiry = BigInt(String(input.expiry_block));
  const current = BigInt(String(input.current_block));
  const recipient = String(input.recipient || '').toLowerCase();
  const conditionRecipient = String(input.condition_recipient || '').toLowerCase();
  const amount = BigInt(String(input.amount));
  const maxTransfer = BigInt(String(input.max_transfer));

  if (regVk !== REGISTERED_VK.toLowerCase() || proofVk !== regVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (balance < minimum || amount > maxTransfer || expiry <= current) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  return { decision: 'APPROVE', reason_code: 'OK' };
}

async function prove(input, decisionStr, taskId) {
  const dec = decisionStr === 'APPROVE' ? '1' : '0';
  const circuitInput = {
    registeredVkHash: BigInt(String(input.registered_vk)).toString(),
    proofVkHash: BigInt(String(input.proof_vk)).toString(),
    minimum: String(input.minimum),
    publicBalance: String(input.public_balance),
    expiryBlock: String(input.expiry_block),
    currentBlock: String(input.current_block),
    recipient: BigInt(String(input.recipient)).toString(),
    conditionRecipient: BigInt(String(input.condition_recipient)).toString(),
    amount: String(input.amount),
    maxTransfer: String(input.max_transfer),
    decision: dec,
    taskId: taskIdField(taskId),
    salt: taskSalt(taskId),
  };
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  log({ event: 'prove', taskId, decision: decisionStr, ms: Date.now() - t0, publicSignals });
  return { proof, publicSignals };
}

function sendSigned(res, status, obj) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = signBody(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
  return body;
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    const started = Date.now();
    try {
      log({ event: 'request', method: req.method, url: req.url, headers: req.headers, body: raw.toString('utf8').slice(0, 4000) });
      if (req.method === 'GET') {
        sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
        return;
      }
      if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
      if (!HMAC_SECRET) {
        log({ event: 'no-secret-yet' });
        // No secret configured yet (pre-registration): still answer preflight-shaped
        // requests unsigned so the platform's probe is observable in the log.
        sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
        return;
      }
      const sig = req.headers['x-agent-games-signature'];
      if (!verifySig(HMAC_SECRET, raw, sig)) {
        log({ event: 'hmac-mismatch' });
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'bad signature' }));
        return;
      }
      let env;
      try { env = JSON.parse(raw.toString('utf8')); }
      catch (_) { sendSigned(res, 200, { ok: true, protocolVersion: 'v1' }); return; }
      const isTask = env && typeof env.type === 'string' && env.type.startsWith('agent-games.proof-gatekeeper');
      if (!isTask) {
        // Preflight probe (or any other signed non-task POST).
        log({ event: 'preflight', type: env && env.type });
        sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
        return;
      }
      // ---- task ----
      const taskId = env.task_id || env.taskId || '';
      const input = env.input || {};
      // Timestamp sanity: reject stale/expired tasks (fail closed).
      const now = Date.now();
      const deadline = env.deadline_at ? Date.parse(env.deadline_at) : NaN;
      if (!isNaN(deadline) && now > deadline) {
        log({ event: 'task-expired', taskId });
        sendSigned(res, 200, { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' });
        return;
      }
      const verdict = decide(input);
      let proof = null, publicSignals = null;
      try {
        const r = await prove(input, verdict.decision, taskId);
        proof = r.proof; publicSignals = r.publicSignals;
      } catch (e) {
        // Proof generation failed: fail closed. A missing/invalid proof costs -2,
        // a wrong approval costs -6, so never approve without a proof.
        log({ event: 'prove-failed', taskId, error: String(e && e.message || e) });
        sendSigned(res, 200, { decision: 'REJECT', reason_code: verdict.reason_code });
        return;
      }
      if (Date.now() - started > 50000) {
        log({ event: 'over-budget', taskId });
        sendSigned(res, 200, { decision: 'REJECT', reason_code: verdict.reason_code });
        return;
      }
      const resp = { decision: verdict.decision, reason_code: verdict.reason_code, proof, public_signals: publicSignals };
      if (input.proof_tx) resp.proof_tx = input.proof_tx;
      log({ event: 'respond', taskId, decision: verdict.decision, reason_code: verdict.reason_code, ms: Date.now() - started });
      sendSigned(res, 200, resp);
    } catch (e) {
      log({ event: 'handler-error', error: String(e && e.message || e) });
      try { sendSigned(res, 200, { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' }); } catch (_) {}
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`gatekeeper agent listening on 0.0.0.0:${PORT} secret=${HMAC_SECRET ? 'set' : 'MISSING'}`);
});
