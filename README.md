# attack-simulation-agent

[![CI](https://github.com/openasy/attack-simulation-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/attack-simulation-agent/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The agent for [OpenAsy Attack Simulation](https://github.com/openasy/attack-simulation) (ADR 0072). It sits on a host
you want to validate detection for, enrols once, then asks the server for the tests to run, runs each **from its own
built-in pack**, cleans up, and reports what it did.

## It runs nothing the server sends

This is the safety boundary of the whole product. The server sends only a test's **pack id** and a random hex
**marker**; the agent:

1. looks the id up in its **own built-in pack** (`agent/pack.ts`) and **refuses** anything it does not have,
2. checks the marker is plain hex, and uses it only as a label (a file or DNS name), never as a command,
3. runs the test's fixed code, with no shell, and
4. cleans up and reports what it did.

The pack is harmless by construction: read the host (`whoami`, `uname`, `id`), create and delete a marker file in a temp
directory, one outbound DNS lookup of a marker name under a reserved test domain, and write and delete the EICAR
anti-malware test string. No credential dumping, no persistence, no privilege escalation, no network scanning, no real
malware. The agent takes no inbound work and holds no power to change the host beyond its own benign tests.

## Run

```bash
openssl rand -hex 32 > openasy-agent-kek   # the agent's own key, seals its secret (ADR 0021)
ATTACKSIM_URL=https://attack-simulation.example.com ATTACKSIM_ENROLL_TOKEN=aie_... docker compose up -d
```

The enrolment token comes from Attack Simulation, under Hosts. The agent needs it once and keeps its own secret
afterwards. The host runs nothing until an admin **allows it for simulation**, with a reason, in the server.

| Variable | Default | |
| --- | --- | --- |
| `ATTACKSIM_URL` | | The address of attack-simulation (required) |
| `ATTACKSIM_ENROLL_TOKEN` | | The enrolment token, needed once on the first start |
| `ATTACKSIM_AGENT_SECRETS_KEY_FILE` | `/run/secrets/openasy-agent-kek` | 32-byte key-encryption key |
| `ATTACKSIM_AGENT_STATE` | `/data/agent.state` | The agent's sealed state (its secret), on the `/data` volume |
| `ATTACKSIM_AGENT_NAME` / `NODE_NAME` | the host's name | The name to enrol under |
| `ATTACKSIM_POLL_SECONDS` | `5` | How often to ask the server for assignments |
| `HEALTH_LISTEN` | `127.0.0.1:2812` | Where `/healthz`, `/readyz` and `/metrics` are served |

`/readyz` is degraded until the agent is enrolled and can reach the server. `/metrics` has
`openasy_attacksim_agent_tests_total`, `openasy_attacksim_agent_tests_refused_total`,
`openasy_attacksim_agent_tests_errored_total` and `openasy_attacksim_agent_pack_size`.

The container runs as an unprivileged user with a read-only root filesystem, no capabilities and `no-new-privileges`.
Its secret lives sealed on its own volume (ADR 0021); losing the volume means an admin removes the host and enrols it
again.

## Develop

```bash
npm install
npm test        # the pack runs harmlessly and cleans up, and the loop refuses any id not in the built-in pack
```

## Licence

AGPL-3.0 (ADR 0008).
