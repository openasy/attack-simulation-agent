// The agent's built-in pack of benign tests (ADR 0072). THIS is the safety boundary of the whole product: the server
// never sends a command, only a test's pack id and a random marker. The agent looks the id up here and runs the fixed
// function below, or refuses. Nothing here is built from anything the server sent; the marker is used only as a label
// (a file name, a DNS name) and is checked to be plain hex before it is ever used.
//
// Every test is harmless by construction and cleans up after itself: it reads its own host, creates and removes its
// own file, or makes one outbound DNS lookup under a reserved test domain. There is no credential access, no
// persistence past the test, no privilege change, no network scan and no real malware (the EICAR string is a standard,
// harmless anti-malware test token). Adding or changing a test is a reviewed code change in this file.
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { lookup } from "node:dns/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

/** What a test reports back. `did` is a short human line; `cleanedUp` says the test left nothing behind. */
export interface TestResult {
  did: string;
  cleanedUp: boolean;
  detail?: string;
}

export interface AgentTest {
  id: string;
  technique: string;
  /** The fixed action. `marker` is plain hex, already checked by the caller; it is a label, never a command. */
  perform: (marker: string) => Promise<TestResult>;
}

/** The reserved test domain markers are looked up under; it does not resolve and carries no data but the name. */
const TEST_DOMAIN = "sim.openasy.test";
/** A command is given this long before it is given up on; a benign discovery command returns at once. */
const CMD_TIMEOUT = 10_000;

/** Runs one fixed program with fixed arguments and no shell, and reports a trimmed first line of its output. */
async function command(file: string, args: string[]): Promise<TestResult> {
  const { stdout } = await run(file, args, { timeout: CMD_TIMEOUT, shell: false, windowsHide: true, maxBuffer: 64 * 1024 });
  const line = stdout.toString().trim().split("\n")[0]?.slice(0, 200) ?? "";
  // Discovery reads only; there is nothing to clean up.
  return { did: `ran ${file} ${args.join(" ")}`.trim(), cleanedUp: true, detail: line };
}

/** The EICAR anti-malware test string, assembled from parts so the source file itself is not a scanner trigger. */
const eicar = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}", "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!", "$H+H*"].join("");

export const PACK: AgentTest[] = [
  { id: "discovery-whoami", technique: "T1033", perform: () => command("whoami", []) },
  { id: "discovery-system-info", technique: "T1082", perform: () => command("uname", ["-a"]) },
  { id: "discovery-account", technique: "T1087.001", perform: () => command("id", []) },
  {
    id: "defense-evasion-marker-file",
    technique: "T1070.004",
    perform: async (marker) => {
      const dir = await mkdtemp(join(tmpdir(), "openasy-sim-"));
      const file = join(dir, `${marker}.marker`);
      try {
        await writeFile(file, `openasy attack-simulation marker ${marker}\n`, { mode: 0o600 });
      } finally {
        // Remove the whole temp directory, so the test leaves nothing behind even on a mid-way failure.
        await rm(dir, { recursive: true, force: true });
      }
      return { did: `created and deleted ${file}`, cleanedUp: true };
    },
  },
  {
    id: "c2-dns-marker-lookup",
    technique: "T1071.004",
    perform: async (marker) => {
      const name = `${marker}.${TEST_DOMAIN}`;
      // The lookup is expected to fail (the name does not exist); the point is the query a network sensor can see.
      const outcome = await lookup(name).then(
        (r) => `resolved to ${r.address}`,
        (err: NodeJS.ErrnoException) => `not resolved (${err.code ?? "error"})`,
      );
      // A DNS query makes no change to the host; nothing to clean up.
      return { did: `looked up ${name}`, cleanedUp: true, detail: outcome };
    },
  },
  {
    id: "execution-eicar-file",
    technique: "T1204.002",
    perform: async (marker) => {
      const dir = await mkdtemp(join(tmpdir(), "openasy-sim-"));
      const file = join(dir, `${marker}.eicar.txt`);
      try {
        await writeFile(file, eicar, { mode: 0o600 });
      } finally {
        await rm(dir, { recursive: true, force: true });
      }
      return { did: `wrote and deleted the EICAR test string in ${file}`, cleanedUp: true };
    },
  },
];

export const packById = new Map(PACK.map((t) => [t.id, t]));
/** The ids the agent reports to the server, so the UI can show what this host can run. */
export const packIds = PACK.map((t) => t.id);

/** A marker is a short hex label the agent puts in a file or DNS name; anything else is refused, never used. */
export const MARKER = /^[0-9a-f]{8,32}$/;
