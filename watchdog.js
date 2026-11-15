// Watchdog for the Proof Gatekeeper agent.
// Keeps agent.js alive, (re)creates the cloudflared quick tunnel, and keeps the
// platform registration in sync (add on first URL, updateAgentEndpoint when the
// tunnel URL changes, then preflight). Runs in a loop; dies on VM restart like
// everything else — run it from a cron for durability.
//   node watchdog.js [--once] [--interval-ms 600000]
// State: watchdog-state.json (agentId, endpointUrl). Secret lives in .env only.
// Never logs the HMAC secret.
'use strict';
const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');
const { callAction } = require('./platform');

const DIR = __dirname;
const PORT = 8787;
const INTERVAL_MS = parseInt(process.env.WATCHDOG_INTERVAL_MS || '600000', 10);
const STATE_FILE = path.join(DIR, 'watchdog-state.json');
const LOG_FILE = path.join(DIR, 'watchdog.log');
const AGENT_PID = path.join(DIR, 'agent.pid');
const TUNNEL_PID = path.join(DIR, 'tunnel.pid');
const TUNNEL_LOG = path.join(DIR, 'tunnel.log');

function log(msg, obj) {
  const line = JSON.stringify({ t: new Date().toISOString(), msg, ...(obj || {}) }) + '\n';
  fs.appendFileSync(LOG_FILE, line);
  console.log(line.trim());
}
function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch (_) { return {}; }
}
function saveState(s) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
  fs.chmodSync(STATE_FILE, 0o600);
}
function pidAlive(pidFile) {
  try {
    const pid = parseInt(fs.readFileSync(pidFile, 'utf8'), 10);
    process.kill(pid, 0);
    return pid;
  } catch (_) { return 0; }
}
function killPid(pidFile) {
  const pid = pidAlive(pidFile);
  if (pid) { try { process.kill(pid, 'SIGTERM'); } catch (_) {} }
}
function agentUp() {
  return fetch(`http://127.0.0.1:${PORT}/`, { signal: AbortSignal.timeout(5000) })
    .then((r) => r.ok).catch(() => false);
}
async function startAgent() {
  killPid(AGENT_PID);
  const child = spawn('node', ['agent.js'], {
    cwd: DIR, detached: true, stdio: ['ignore', fs.openSync(path.join(DIR, 'agent.log'), 'a'), fs.openSync(path.join(DIR, 'agent.log'), 'a')],
    env: { ...process.env, PORT: String(PORT) },
  });
  child.unref();
  fs.writeFileSync(AGENT_PID, String(child.pid));
  for (let i = 0; i < 10; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    if (await agentUp()) { log('agent-started', { pid: child.pid }); return true; }
  }
  log('agent-start-failed');
  return false;
}
function startTunnel() {
  killPid(TUNNEL_PID);
  try { fs.unlinkSync(TUNNEL_LOG); } catch (_) {}
  const out = fs.openSync(TUNNEL_LOG, 'a');
  const child = spawn(path.join(DIR, 'cloudflared'), ['tunnel', '--url', `http://127.0.0.1:${PORT}`], {
    cwd: DIR, detached: true, stdio: ['ignore', out, out],
  });
  child.unref();
  fs.writeFileSync(TUNNEL_PID, String(child.pid));
  return child.pid;
}
async function waitForTunnelUrl(timeoutMs = 45000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const txt = fs.readFileSync(TUNNEL_LOG, 'utf8');
      // Real quick-tunnel hostnames are random words; EXCLUDE api.trycloudflare.com
      // (the API host appears in the log's error text and is not a tunnel URL).
      const m = txt.match(/https:\/\/(?!api\.)([a-z0-9-]+\.trycloudflare\.com)/);
      if (m) return 'https://' + m[1];
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 2000));
  }
  return null;
}
function setEnvSecret(secret) {
  const envPath = path.join(DIR, '.env');
  let txt = '';
  try { txt = fs.readFileSync(envPath, 'utf8'); } catch (_) {}
  if (/^AGENT_GAMES_HMAC_SECRET=/m.test(txt)) txt = txt.replace(/^AGENT_GAMES_HMAC_SECRET=.*$/m, `AGENT_GAMES_HMAC_SECRET=${secret}`);
  else txt += (txt.endsWith('\n') || txt === '' ? '' : '\n') + `AGENT_GAMES_HMAC_SECRET=${secret}\n`;
  fs.writeFileSync(envPath, txt);
  fs.chmodSync(envPath, 0o600);
}
const stripScheme = (u) => u.replace(/^https?:\/\//, '');

async function pass() {
  log('pass-start');
  if (!(await agentUp())) {
    log('agent-down-restarting');
    if (!(await startAgent())) return;
  }
  const state = loadState();
  // Tunnel: reuse if the recorded URL still serves, else (re)create.
  let url = null;
  const tunnelPid = pidAlive(TUNNEL_PID);
  if (tunnelPid && state.endpointUrl) {
    try {
      const r = await fetch(state.endpointUrl, { signal: AbortSignal.timeout(8000) });
      if (r.ok) url = state.endpointUrl.replace(/\/agent$/, '');
    } catch (_) { /* tunnel dead, recreate */ }
  }
  if (!url) {
    startTunnel();
    url = await waitForTunnelUrl();
    if (!url) {
      log('tunnel-failed', { hint: 'cloudflared quick-tunnel API blocked (403) or unreachable; retry next pass' });
      return;
    }
    log('tunnel-up', { url });
  }
  const endpoint = url + '/agent';
  const endpointStripped = stripScheme(endpoint);
  // Verify the tunnel actually serves our agent before registering.
  try {
    const r = await fetch(endpoint, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) { log('tunnel-url-not-serving', { endpoint, status: r.status }); return; }
  } catch (e) {
    log('tunnel-url-not-serving', { endpoint, error: String(e && e.message || e) });
    return;
  }
  // addAgentAction REQUIRES a repository URL (platform validation).
  // Set it via env AGENT_REPO_URL (public GitHub repo of this agent's code).
  const repoUrl = process.env.AGENT_REPO_URL || '';
  if (!repoUrl && !state.agentId) {
    log('repo-url-missing', { hint: 'set AGENT_REPO_URL to the public GitHub repo of the agent code; registration skipped' });
    return;
  }
  if (!state.agentId) {
    log('registering-agent', { endpoint });
    const { ret, httpStatus } = await callAction('addAgentAction', [{
      name: 'jackdefi-gatekeeper', events: ['Proof Gatekeeper'], repoUrl, endpoint: endpointStripped,
    }]);
    if (!ret || !ret.ok) {
      log('register-failed', { httpStatus, error: ret && ret.error, rawHead: ret ? undefined : 'see platform raw' });
      return;
    }
    log('registered', { agentId: ret.agentId, name: ret.name, secret: ret.secret ? 'RECEIVED (saved, not logged)' : 'MISSING' });
    if (ret.secret) setEnvSecret(ret.secret);
    saveState({ ...state, agentId: ret.agentId, endpointUrl: endpoint, registeredAt: new Date().toISOString() });
    await startAgent(); // pick up the real HMAC secret
  } else if (state.endpointUrl !== endpoint) {
    log('endpoint-changed', { old: state.endpointUrl, new: endpoint });
    const { ret } = await callAction('updateAgentEndpoint', [state.agentId, endpointStripped]);
    if (!ret || !ret.ok) { log('update-endpoint-failed', { error: ret && ret.error }); return; }
    saveState({ ...state, endpointUrl: endpoint });
    log('endpoint-updated');
  } else {
    log('endpoint-unchanged', { endpoint });
  }
  // Preflight to confirm the platform can reach + verify us.
  const { ret: pf } = await callAction('preflightAgent', [loadState().agentId]);
  if (pf && pf.ok) log('preflight-ok', { latencyMs: pf.latencyMs });
  else log('preflight-failed', { kind: pf && pf.kind, error: pf && pf.error });
}

(async () => {
  const once = process.argv.includes('--once');
  await pass();
  if (once) return;
  setInterval(() => { pass().catch((e) => log('pass-error', { error: String(e && e.message || e) })); }, INTERVAL_MS);
  log('watchdog-looping', { intervalMs: INTERVAL_MS });
})();
