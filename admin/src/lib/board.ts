import "server-only";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { config } from "./config";
import { Session, SESSION_COOKIE, unseal } from "./session";

export class BoardError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

export async function currentSession(): Promise<Session | null> {
  return unseal<Session>((await cookies()).get(SESSION_COOKIE)?.value);
}

/** Call the board's Admin API as the signed-in person. Never runs in the browser. */
export async function board<T = unknown>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  const session = await currentSession();
  if (!session) redirect("/auth/login");
  const response = await fetch(`${config.boardUrl}/admin/api${path}`, {
    method: init?.method ?? "GET",
    headers: {
      Authorization: `Bearer ${session.accessToken}`,
      ...(init?.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
  });
  if (response.status === 401) redirect("/auth/login");
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new BoardError(data.error ?? "error", data.message ?? response.statusText, response.status);
  return data as T;
}

// ── shapes returned by the Admin API ────────────────────────────────────────

export type Me = { id: string; name: string; role: "owner" | "approver" | "viewer"; email: string | null };
export type Overview = {
  halted: boolean;
  agents_by_status: Record<string, number>;
  tasks: { project_id: string; status: string; n: number }[];
  pending_approvals: number;
  deferred: number;
  active_agents: { id: string; client: string; last_seen: string }[];
};
export type Agent = {
  id: string;
  owner: string;
  client: string;
  status: "active" | "paused" | "banned";
  last_seen: string | null;
  created_at: string;
  root_mandate_id: string | null;
  projects: string[];
  live_tokens: number;
};
export type Project = {
  id: string;
  name: string;
  production: boolean;
  frozen: boolean;
  created_by: string;
  created_at: string;
  open_tasks: number;
};
export type Mandate = {
  id: string;
  parent_id: string | null;
  issuer_kind: "human" | "agent";
  issuer: string;
  holder: string;
  scope: string[];
  limits: Record<string, number>;
  usage: Record<string, number>;
  delegations_left: number;
  depth: number;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
};
export type Task = {
  id: string;
  project_id: string;
  title: string;
  body: string;
  action: string;
  status: string;
  created_by: string;
  delegate_to: string | null;
  assignee: string | null;
  deferred: boolean;
  defer_reason: string | null;
  needed_scope: string[] | null;
  result: unknown;
  approved_by: string | null;
  created_at: string;
  updated_at: string;
};
export type Entry = {
  id: number;
  at: string;
  project_id: string | null;
  task_id: string | null;
  agent_id: string | null;
  actor: string;
  action: string;
  outcome: string;
  mandate_chain: string[];
  payload: unknown;
  payload_erased: boolean;
};
export type Trace = {
  task: Task;
  entries: Entry[];
  mandates: Pick<Mandate, "id" | "parent_id" | "issuer_kind" | "issuer" | "holder" | "scope" | "revoked_at" | "expires_at">[];
};
