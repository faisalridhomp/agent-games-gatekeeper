# Proof Gatekeeper — zkVerify Agent Games (Season 01)

Public HTTPS agent endpoint for the **Proof Gatekeeper** track of zkVerify's
Agent Games. The platform POSTs signed transfer-request tasks; the agent
decides APPROVE/REJECT, generates a Groth16 ZK proof locally with snarkjs,
and returns the decision + proof + public signals, all HMAC-signed.

## Protocol (from https://agentgames.zkverify.io/build)

Task envelope (`POST` to the registered endpoint):

```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_...",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x7d...91", "proof_vk": "0x13...aa",
    "minimum": "1000", "public_balance": "1460",
    "expiry_block": 8430000, "current_block": 8420000,
    "recipient": "0xDe42...9f01", "condition_recipient": "0xDe42...9f01",
    "amount": "500", "max_transfer": "1000", "proof_tx": "0xa8...2c"
  }
}
```

Response (200, signed with `x-agent-games-signature` over the raw body):

```json
{ "decision": "APPROVE", "reason_code": "OK",
  "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...] },
  "public_signals": ["...", "..."] }
```

- Inbound requests are HMAC-SHA256 verified against the raw body
  (`x-agent-games-signature` header) **before** parsing.
- APPROVE only when every check passes: VK matches the registered key
  (`0x6b79c6…d77b0`), balance ≥ minimum, amount ≤ max, recipient matches,
  expiry ahead of current block. Otherwise REJECT with
  `VK_SUBSTITUTION` / `RECIPIENT_MISMATCH` / `THRESHOLD_MISMATCH`.
- The circuit enforces `decision == 1` iff all checks pass, so a wrong
  decision cannot even produce a witness.
- Preflight (any signed non-task POST): `{ ok: true, protocolVersion: "v1" }`.
- 60 s hard deadline; fail closed on timeout / error / uncertainty.
- Score: +12 correct, −6 approving a trap, −3 rejecting a valid request,
  −2 timeout/offline, −2 proof fails to verify, plus a reliability bonus.

## Run

```bash
npm install
cp .env.example .env   # set AGENT_GAMES_HMAC_SECRET from the dashboard
node agent.js          # listens on 127.0.0.1:8787; put a public HTTPS tunnel in front
```

`watchdog.js` keeps the agent + tunnel alive and keeps the platform
registration in sync (registers on first tunnel URL, updates the endpoint
when the tunnel URL changes, then runs preflight). Set `AGENT_REPO_URL`
to this repo's public URL before first registration — the platform
requires a repository URL.

## Files

- `agent.js` — the endpoint (HMAC, decision, snarkjs proving, signed responses)
- `platform.js` — client for the platform's Next.js server actions
  (register / update endpoint / rotate secret / preflight / practice dispatch)
- `watchdog.js` — keeper + tunnel retry + auto-register/update
- `gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` —
  public circuit artifacts (vkHash
  `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`)

## Secrets

Never commit `.env`. The HMAC secret comes from the Agent Games dashboard
("Rotate Secret", shown once). The Kurier API key is optional — it only
adds the on-chain `proof_tx` audit pointer; the agent answers fully
without it.
