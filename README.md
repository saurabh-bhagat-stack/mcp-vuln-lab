# mcp-vuln-lab

A **Docker-isolated, deliberately-vulnerable** set of **AI / LLM / MCP targets** for exercising and
benchmarking MCP security scanners and LLM/agent pentest tooling. Every target produces **real**
vulnerable behaviour — genuine file reads, shell exec, outbound SSRF, un-scoped object reads, leaked
secrets, poisoned tool output — so your scanner confirms on true signals, not on planted markers.

Six targets across three difficulty tiers (**easy / medium / hard**) reproduce 50+ scenarios drawn from
real-world CVEs and public research. The **hard** tier also includes *negative controls* (rate-limiting
enforced, CORS locked down) so you can check your tooling does **not** false-positive.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/run-docker-2496ED)
![Purpose](https://img.shields.io/badge/use-authorized%20testing%20only-red)

> ⚠️ **Intentionally insecure. Run only on your own machine, never on a public or shared host.**
> Containers bind to `127.0.0.1` only and mount **no** host volumes. They *do* need outbound internet
> so out-of-band SSRF / exfil can be confirmed (e.g. via Burp Collaborator).

---

## Targets

| Tier | Target | Port | Endpoint | Models |
|------|--------|------|----------|--------|
| easy | easy-mcp | 8911 | `http://127.0.0.1:8911/mcp` | Unauthenticated internal-tools MCP server |
| easy | easy-chat | 8912 | `http://127.0.0.1:8912/v1/chat/completions` | Guardrail-less support chatbot |
| medium | medium-mcp | 8921 | `http://127.0.0.1:8921/mcp` | "Graph connector" MCP: token present but validated nowhere |
| medium | medium-agent | 8922 | `http://127.0.0.1:8922/v1/chat/completions` | Chatbot **with tools** (hijack, exfil, memory) |
| hard | hard-mcp | 8931 | `http://127.0.0.1:8931/mcp` | Multi-tenant M365 connector; subtle, chained bugs |
| hard | hard-agent | 8932 | `http://127.0.0.1:8932/v1/chat/completions` | Multi-agent orchestrator with an A2A card |

Full **vulnerability → check → real CVE/disclosure** map: **[SCENARIOS.md](SCENARIOS.md)**.

## Coverage (50+ scenarios)

**MCP:** unauthenticated access · token-not-validated · `alg=none`/wrong-audience · client-supplied
(unbound) session id · path traversal · command injection · SSTI · SQL & OData injection · SSRF→cloud
metadata · tool poisoning / tool-name injection / tool shadowing / rug-pull · SAS pre-auth URL exposure ·
stored indirect injection · SSE frame-splitting · reverse-request abuse · unbounded consumption ·
cross-tenant IDOR / confused deputy · weak OAuth2 discovery · cleartext · permissive CORS.

**Chatbot / agent:** system-prompt & seeded-secret leakage · jailbreak corpus · unsafe output (XSS) ·
model/endpoint disclosure · tool-call hijack · attacker-directed fetch (exfil) · cross-turn memory
poisoning · parameter-smuggling / injected system message · A2A agent-card weaknesses · inter-agent
(spoofed-peer) injection · tool-chaining exfil.

Each maps to a real CVE or public disclosure — e.g. **CVE-2025-6514** (mcp-remote RCE), **CVE-2025-49596**
(MCP Inspector), **CVE-2025-53110** (filesystem MCP traversal), **CVE-2025-32711** (M365 Copilot EchoLeak),
**CVE-2023-29374** (LangChain eval RCE). See [SCENARIOS.md](SCENARIOS.md) for the full list and sources.

---

## Run

Docker is the only requirement.

```bash
./lab.sh up            # build + start all six; also: ./lab.sh ps | logs [name] | down | rebuild
```

Or with the compose plugin:

```bash
docker compose up --build -d
```

Both publish the ports above to `127.0.0.1`. Stop with `./lab.sh down` (or `docker compose down`).

## Point a scanner at it

### MCP targets
Give your scanner the endpoint (e.g. `http://127.0.0.1:8911/mcp`). **Auth:** easy = none; medium/hard =
`Bearer` with **any** value (e.g. `alice-token`) — the point is the token is never validated. Discover the
tools, enable active probing, and scan.

### Chatbot / agent targets
They are OpenAI-compatible, e.g.:

```bash
curl -s http://127.0.0.1:8912/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"contoso-bot","messages":[{"role":"user","content":"hello"}]}'
```

### Multi-identity / multi-scan checks (hard)
- **Cross-tenant IDOR / confused deputy:** replay a read tool as a **second** identity (any different Bearer).
- **Tool shadowing (cross-server):** scan **both** medium-mcp and hard-mcp — they share tool names on purpose.
- **Rug-pull:** scan hard-mcp **twice** — a tool's definition changes between scans.

## Using it with Djinn
This lab was built to validate the **Djinn** Burp extension; the finding titles in
[SCENARIOS.md](SCENARIOS.md) are what Djinn should file, so it doubles as a Djinn scorecard. It is not
coupled to Djinn in any way — point any MCP/AI pentest tool at the same endpoints.

## How it works
Lightweight FastAPI + uvicorn. `app/mcp_core.py` is a minimal MCP JSON-RPC/SSE server framework;
`app/chat_core.py` is a weak pseudo-LLM chat/agent engine; `app/vulnlib.py` holds the shared vulnerable
behaviours; `app/{easy,medium,hard}_{mcp,chat,agent}.py` wire each target. No AI model is required to run it.

## License
[MIT](LICENSE) — for **authorized security testing and education only**.
