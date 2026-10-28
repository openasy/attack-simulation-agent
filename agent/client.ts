// Everything the agent sends goes to the Attack Simulation API, and only that way (ADR 0023): the server never calls
// the agent and never sends it anything to run. The agent asks for its assignments and is answered with pack ids and
// markers; it reports what it did. Each call carries the agent's report of itself.
export interface Report {
  version: string;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  packIds: string[];
}

export interface Assignment {
  stepId: string;
  packId: string;
  marker: string;
  technique: string;
}

export interface StepResult {
  stepId: string;
  status: "done" | "error" | "refused";
  did?: string;
  cleanedUp?: boolean;
  detail?: string;
  error?: string;
}

export class ServerError extends Error {
  readonly status: number | undefined;
  readonly code: string | undefined;
  constructor(status: number | undefined, code: string | undefined, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call<T>(url: string, path: string, init: { secret?: string; body: unknown }): Promise<T> {
  let res: Response;
  try {
    res = await fetch(new URL(path, url), {
      method: "POST",
      headers: {
        ...(init.secret && { authorization: `Bearer ${init.secret}` }),
        "content-type": "application/json",
        "user-agent": "openasy-attack-simulation-agent",
      },
      body: JSON.stringify(init.body),
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    throw new ServerError(undefined, "unreachable", `attack-simulation at ${url} is unreachable: ${(err as Error).message}`);
  }
  if (!res.ok) {
    const p = (await res.json().catch(() => ({}))) as { code?: string; detail?: string; title?: string };
    throw new ServerError(res.status, p.code, p.detail ?? p.title ?? `${res.status}`);
  }
  return (await res.json()) as T;
}

export const enroll = (url: string, token: string, name: string, report: Report) =>
  call<{ hostId: string; secret: string }>(url, "/api/v1/agent/enroll", { body: { token, name, report } });
export const getAssignments = (url: string, secret: string, report: Report) =>
  call<{ assignments: Assignment[] }>(url, "/api/v1/agent/assignments", { secret, body: { report } });
export const sendResult = (url: string, secret: string, report: Report, result: StepResult) =>
  call<{ recorded: number }>(url, "/api/v1/agent/results", { secret, body: { report, ...result } });
