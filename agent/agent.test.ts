import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAgent } from "./agent.ts";
import { createKeyring } from "./kek.ts";

const keyring = createKeyring(Buffer.alloc(32, 7));

/** A fake server that enrols the agent, hands out the assignments it is given, and collects the results. */
function fakeServer(assignments: Array<{ stepId: string; packId: string; marker: string; technique: string }>) {
  const results: Array<Record<string, unknown>> = [];
  let served = false;
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const json = (status: number, data: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(data));
      if (req.url === "/api/v1/agent/enroll") return json(200, { hostId: "h1", secret: "aia_test" });
      if (req.url === "/api/v1/agent/assignments") return json(200, { assignments: served ? [] : ((served = true), assignments) });
      if (req.url === "/api/v1/agent/results") {
        results.push(JSON.parse(body));
        return json(200, { recorded: 1 });
      }
      json(404, { code: "not-found" });
    });
  });
  return { server, results };
}

const built: Server[] = [];
afterEach(() => built.forEach((s) => s.close()));

async function run(assignments: Array<{ stepId: string; packId: string; marker: string; technique: string }>) {
  const { server, results } = fakeServer(assignments);
  built.push(server);
  await new Promise<void>((r) => server.listen(0, r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const statePath = join(mkdtempSync(join(tmpdir(), "asim-agent-")), "agent.state");
  const agent = createAgent({ url, version: "0.1.0", name: "test-host", state: {}, statePath, keyring, enrollToken: "aie_token", root: "/" });
  await agent.round();
  return { results, status: agent.status };
}

describe("the agent loop", () => {
  it("runs a test from the pack and reports that it ran and cleaned up", async () => {
    const { results, status } = await run([{ stepId: "s1", packId: "discovery-whoami", marker: "00112233aabbccdd", technique: "T1033" }]);
    expect(status.ran).toBe(1);
    expect(results[0]).toMatchObject({ stepId: "s1", status: "done", cleanedUp: true });
  });

  it("refuses a pack id it does not have, without running anything", async () => {
    const { results, status } = await run([{ stepId: "s2", packId: "read-etc-shadow", marker: "00112233aabbccdd", technique: "T1003" }]);
    expect(status.ran).toBe(0);
    expect(status.refusedTests).toBe(1);
    expect(results[0]).toMatchObject({ stepId: "s2", status: "refused" });
    expect(String(results[0]!.detail)).toContain("no test with id");
  });

  it("refuses an assignment whose marker is not plain hex", async () => {
    const { results, status } = await run([{ stepId: "s3", packId: "defense-evasion-marker-file", marker: "../etc/passwd", technique: "T1070.004" }]);
    expect(status.ran).toBe(0);
    expect(status.refusedTests).toBe(1);
    expect(results[0]).toMatchObject({ stepId: "s3", status: "refused" });
  });
});
