import type { IncomingMessage, ServerResponse } from "node:http";
import type { Status } from "./agent.ts";
import { packIds } from "./pack.ts";

function send(res: ServerResponse, status: number, body: string, type = "application/json") {
  res.writeHead(status, { "content-type": type, "content-length": Buffer.byteLength(body), "x-content-type-options": "nosniff" });
  res.end(body);
}

/** Health and metrics for the agent (ADR 0017). The agent has no API of its own and takes no inbound work. */
export function createAgentHandler(version: string, s: Status) {
  return (req: IncomingMessage, res: ServerResponse) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    if (path === "/healthz") return send(res, 200, JSON.stringify({ status: "ok" }));
    if (path === "/readyz") {
      const problems = [
        !s.enrolled && "not enrolled",
        s.refused && "secret refused",
        !s.serverOk && `server unreachable${s.lastError ? `: ${s.lastError}` : ""}`,
      ].filter(Boolean);
      return send(res, problems.length ? 503 : 200, JSON.stringify(problems.length ? { status: "degraded", problems } : { status: "ready" }));
    }
    if (path === "/metrics") {
      const lines = [
        "# HELP openasy_build_info Build information.",
        "# TYPE openasy_build_info gauge",
        `openasy_build_info{product="attack-simulation-agent",version="${version}"} 1`,
        "# HELP openasy_attacksim_agent_tests_total Tests this agent ran from its built-in pack.",
        "# TYPE openasy_attacksim_agent_tests_total counter",
        `openasy_attacksim_agent_tests_total ${s.ran}`,
        "# HELP openasy_attacksim_agent_tests_refused_total Assignments refused because the id is not in the built-in pack.",
        "# TYPE openasy_attacksim_agent_tests_refused_total counter",
        `openasy_attacksim_agent_tests_refused_total ${s.refusedTests}`,
        "# HELP openasy_attacksim_agent_tests_errored_total Tests from the pack that errored while running.",
        "# TYPE openasy_attacksim_agent_tests_errored_total counter",
        `openasy_attacksim_agent_tests_errored_total ${s.errored}`,
        "# HELP openasy_attacksim_agent_pack_size Tests in the agent's built-in pack.",
        "# TYPE openasy_attacksim_agent_pack_size gauge",
        `openasy_attacksim_agent_pack_size ${packIds.length}`,
        "# HELP openasy_attacksim_agent_last_contact_timestamp_seconds Last successful call to the server; 0 before the first.",
        "# TYPE openasy_attacksim_agent_last_contact_timestamp_seconds gauge",
        `openasy_attacksim_agent_last_contact_timestamp_seconds ${s.lastContactAt ? Math.floor(Date.parse(s.lastContactAt) / 1000) : 0}`,
      ];
      return send(res, 200, lines.join("\n") + "\n", "text/plain; version=0.0.4");
    }
    send(res, 404, JSON.stringify({ status: "not found" }));
  };
}
