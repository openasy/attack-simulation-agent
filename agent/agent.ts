// The loop: enrol once, then poll for the tests this host should run, run each from the built-in pack, and report
// what it did. The server being down never leaves a mess: a test runs only when it is handed over, and it cleans up
// after itself. The agent runs nothing the server sends as text; it only maps a pack id to its own fixed code (ADR 0072).
import { enroll, getAssignments, sendResult, ServerError, type Assignment, type Report, type StepResult } from "./client.ts";
import { facts } from "./host.ts";
import type { Keyring } from "./kek.ts";
import { log } from "./log.ts";
import { MARKER, packById, packIds } from "./pack.ts";
import { saveState, type AgentState } from "./state.ts";

export interface AgentOptions {
  url: string;
  version: string;
  name: string;
  state: AgentState;
  statePath: string;
  keyring: Keyring;
  enrollToken?: string;
  /** Where the host's root is mounted, for its os-release. */
  root: string;
}

export interface Status {
  enrolled: boolean;
  /** The server refused the agent's secret: the host was removed. Nothing more is tried until it enrols again. */
  refused: boolean;
  serverOk: boolean;
  lastError: string | null;
  lastContactAt: string | null;
  /** Tests run, refused (an id this agent does not have) and that errored, since the start. */
  ran: number;
  refusedTests: number;
  errored: number;
  lastRunAt: string | null;
}

export function createAgent(o: AgentOptions) {
  const status: Status = {
    enrolled: !!o.state.secret,
    refused: false,
    serverOk: false,
    lastError: null,
    lastContactAt: null,
    ran: 0,
    refusedTests: 0,
    errored: 0,
    lastRunAt: null,
  };
  const host = facts(o.root);
  const report = (): Report => ({ version: o.version, ...host, packIds });

  const failed = (err: unknown) => {
    const e = err as ServerError;
    status.serverOk = false;
    status.lastError = e.message;
    if (e.status === 401 && status.enrolled) {
      status.refused = true;
      status.lastError =
        "The server refused this agent's secret: the host was removed there. Delete the agent's /data volume and start it with a new enrolment token.";
      log("error", "secret refused", { error: e.message });
    } else log("warn", "server call failed", { status: e.status, error: e.message });
  };
  const ok = () => {
    status.serverOk = true;
    status.lastError = null;
    status.lastContactAt = new Date().toISOString();
  };

  /** Enrols once with the token; afterwards the agent has its own secret, kept sealed in its state. */
  async function ensureEnrolled(): Promise<boolean> {
    if (status.refused) return false;
    if (o.state.secret) return true;
    if (!o.enrollToken) {
      status.lastError = "Not enrolled: make an enrolment token under Hosts, and start the agent with ATTACKSIM_ENROLL_TOKEN";
      return false;
    }
    try {
      const r = await enroll(o.url, o.enrollToken, o.name, report());
      o.state.hostId = r.hostId;
      o.state.secret = r.secret;
      status.enrolled = true;
      try {
        saveState(o.statePath, o.keyring, o.state);
      } catch (err) {
        log("error", "enrolled, but the secret could not be saved: after a restart the host must be removed in the server and enrolled again", {
          path: o.statePath,
          error: String(err),
        });
      }
      ok();
      log("info", "enrolled", { host: o.name, hostId: r.hostId });
      return true;
    } catch (err) {
      failed(err);
      return false;
    }
  }

  /** Runs one assigned test from the built-in pack, or refuses an id this agent does not have. */
  async function perform(a: Assignment): Promise<StepResult> {
    const test = packById.get(a.packId);
    if (!test) {
      // The safety boundary: an id not in this agent's own pack is never run, whatever the server sent.
      status.refusedTests++;
      log("warn", "refused a test not in the built-in pack", { packId: a.packId });
      return { stepId: a.stepId, status: "refused", detail: `This agent has no test with id ${a.packId}; nothing was run.` };
    }
    if (!MARKER.test(a.marker)) {
      status.refusedTests++;
      return { stepId: a.stepId, status: "refused", detail: "The marker is not a plain hex label; nothing was run." };
    }
    try {
      const r = await test.perform(a.marker);
      status.ran++;
      status.lastRunAt = new Date().toISOString();
      log("info", "test ran", { packId: a.packId, technique: a.technique, cleanedUp: r.cleanedUp });
      return { stepId: a.stepId, status: "done", did: r.did, cleanedUp: r.cleanedUp, detail: r.detail };
    } catch (err) {
      status.errored++;
      return { stepId: a.stepId, status: "error", error: (err as Error).message.slice(0, 500), cleanedUp: true };
    }
  }

  /** Asks for the tests this host should run, runs each, and reports what it did. One step at a time. */
  async function round() {
    if (!(await ensureEnrolled())) return;
    let got: { assignments: Assignment[] };
    try {
      got = await getAssignments(o.url, o.state.secret!, report());
      ok();
    } catch (err) {
      failed(err);
      return;
    }
    for (const a of got.assignments) {
      const result = await perform(a);
      try {
        await sendResult(o.url, o.state.secret!, report(), result);
        ok();
      } catch (err) {
        // The step is still 'running' on the server; the next round picks nothing new up, but a report that did not
        // land is simply retried by the operator restarting, not by re-running the test. Report the failure loudly.
        failed(err);
        log("error", "a result did not reach the server", { stepId: a.stepId, status: result.status });
      }
    }
  }

  return { round, status };
}

export type Agent = ReturnType<typeof createAgent>;
