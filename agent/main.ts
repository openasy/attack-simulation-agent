import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAgent } from "./agent.ts";
import { createAgentHandler } from "./app.ts";
import { hostName } from "./host.ts";
import { createKeyring } from "./kek.ts";
import { log } from "./log.ts";
import { loadState } from "./state.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const env = process.env;
const url = env.ATTACKSIM_URL;
if (!url) {
  log("error", "ATTACKSIM_URL is required: the address of attack-simulation, such as https://attack-simulation.example.com");
  process.exit(1);
}
if (!url.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1|[a-z0-9-]+)(:\d+)?(\/|$)/.test(url))
  // Plain http only to a name in the same compose network or this host; across a network the secret needs TLS (ADR 0026).
  log("warn", "ATTACKSIM_URL is not https: the agent's secret crosses the network in clear", { url });
const keyFile = env.ATTACKSIM_AGENT_SECRETS_KEY_FILE ?? "/run/secrets/openasy-agent-kek";
let kek: Buffer;
try {
  const text = readFileSync(keyFile, "utf8").trim();
  kek = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, "hex") : Buffer.from(text, "base64");
  if (kek.length !== 32) throw new Error("not 32 bytes");
} catch (err) {
  // The agent's secret speaks for its host: it is never kept in the clear (ADR 0021).
  log("error", "no key-encryption key: mount 32 random bytes (openssl rand -hex 32)", { file: keyFile, error: String(err) });
  process.exit(1);
}
const keyring = createKeyring(kek);
const statePath = env.ATTACKSIM_AGENT_STATE ?? "/data/agent.state";
const root = env.HOST_ROOT ?? "/host";
const name = hostName(root, env);
const agent = createAgent({
  url,
  version,
  name,
  state: loadState(statePath, keyring),
  statePath,
  keyring,
  enrollToken: env.ATTACKSIM_ENROLL_TOKEN || undefined,
  root,
});

const [healthHost, healthPort] = (env.HEALTH_LISTEN ?? "127.0.0.1:2812").split(/:(?=\d+$)/);
const health = createServer(createAgentHandler(version, agent.status));
health.listen(Number(healthPort), healthHost, () =>
  log("info", "attack-simulation-agent started", { version, host: name, server: url, enrolled: agent.status.enrolled, health: `${healthHost}:${healthPort}` }),
);

const number = (n: string, fallback: number, min: number, max: number) => {
  const v = Number(env[n] ?? fallback);
  if (!Number.isFinite(v) || v < min || v > max) throw new Error(`${n} must be a number from ${min} to ${max}`);
  return v;
};

// One round at a time: the agent never runs a test while a previous round is still running or reporting.
let busy = false;
const tick = () => {
  if (busy) return;
  busy = true;
  agent
    .round()
    .catch((err: unknown) => log("error", "round failed", { error: String(err) }))
    .finally(() => (busy = false));
};
setTimeout(tick, 1000);
const timer = setInterval(tick, number("ATTACKSIM_POLL_SECONDS", 5, 1, 300) * 1000);

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  clearInterval(timer);
  health.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
