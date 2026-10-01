"use server";

import { revalidatePath } from "next/cache";
import { board, BoardError } from "@/lib/board";

export type ActionState = { ok?: string; error?: string; secret?: string } | null;

/** Run a board call; refusals come back as a message for the form, not a crash. */
async function run(fn: () => Promise<ActionState | void>, paths: string[]): Promise<ActionState> {
  try {
    const out = await fn();
    paths.forEach((p) => revalidatePath(p));
    return out ?? { ok: "Done." };
  } catch (err) {
    if (err instanceof BoardError) return { error: `${err.message} (${err.code})` };
    throw err;
  }
}

const text = (f: FormData, k: string) => String(f.get(k) ?? "").trim();
const list = (f: FormData, k: string) =>
  text(f, k)
    .split(/[\s,]+/)
    .filter(Boolean);

export async function setKillSwitch(_: ActionState, form: FormData): Promise<ActionState> {
  const halted = form.get("halted") === "true";
  if (halted && text(form, "confirm") !== "HALT") return { error: 'Type HALT to confirm.' };
  return run(async () => {
    await board("/kill-switch", { method: "POST", body: { halted } });
    return { ok: halted ? "Every agent is stopped." : "Agents may run again." };
  }, ["/"]);
}

export async function decideTask(_: ActionState, form: FormData): Promise<ActionState> {
  const id = text(form, "id");
  const decision = text(form, "decision");
  return run(() => board(`/tasks/${id}/${decision}`, { method: "POST" }).then(() => undefined), ["/approvals", "/"]);
}

export async function registerAgent(_: ActionState, form: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await board<{ agent_id: string; token: string; connector_path: string }>("/agents", {
      method: "POST",
      body: {
        id: text(form, "id"),
        client: text(form, "client"),
        projects: form.getAll("projects").map(String),
        delegations: Number(text(form, "delegations") || 2),
        days: Number(text(form, "days") || 30),
      },
    });
    return { ok: `Registered ${out.agent_id}. Connector path: ${out.connector_path}`, secret: out.token };
  }, ["/agents"]);
}

export async function setAgentStatus(_: ActionState, form: FormData): Promise<ActionState> {
  return run(
    () => board(`/agents/${text(form, "id")}/status`, { method: "POST", body: { status: text(form, "status") } }).then(() => undefined),
    ["/agents", "/"],
  );
}

export async function issueToken(_: ActionState, form: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await board<{ token: string }>(`/agents/${text(form, "id")}/tokens`, { method: "POST", body: { days: 30 } });
    return { ok: "New token (shown once):", secret: out.token };
  }, ["/agents"]);
}

export async function revokeTokens(_: ActionState, form: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await board<{ revoked: number }>(`/agents/${text(form, "id")}/tokens`, { method: "DELETE" });
    return { ok: `Revoked ${out.revoked} token(s).` };
  }, ["/agents"]);
}

export async function addProject(_: ActionState, form: FormData): Promise<ActionState> {
  return run(
    () =>
      board("/projects", {
        method: "POST",
        body: { id: text(form, "id"), name: text(form, "name"), production: form.get("production") === "on" },
      }).then(() => undefined),
    ["/projects"],
  );
}

export async function setProjectFlag(_: ActionState, form: FormData): Promise<ActionState> {
  const flag = text(form, "flag");
  return run(
    () =>
      board(`/projects/${text(form, "id")}`, { method: "PATCH", body: { [flag]: text(form, "value") === "true" } }).then(
        () => undefined,
      ),
    ["/projects", "/"],
  );
}

export async function issueMandate(_: ActionState, form: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await board<{ mandate_id: string }>("/mandates", {
      method: "POST",
      body: {
        holder: text(form, "holder"),
        scope: list(form, "scope"),
        delegations: Number(text(form, "delegations") || 1),
        days: Number(text(form, "days") || 30),
      },
    });
    return { ok: `Issued mandate ${out.mandate_id}.` };
  }, ["/mandates"]);
}

export async function revokeMandate(_: ActionState, form: FormData): Promise<ActionState> {
  return run(async () => {
    const out = await board<{ descendant_mandates: number; tasks_stopped: number }>(`/mandates/${text(form, "id")}/revoke`, {
      method: "POST",
    });
    return { ok: `Revoked, with ${out.descendant_mandates} mandate(s) below it; ${out.tasks_stopped} task(s) stopped.` };
  }, ["/mandates", "/"]);
}

export async function addHuman(_: ActionState, form: FormData): Promise<ActionState> {
  return run(
    () =>
      board("/humans", {
        method: "POST",
        body: { id: text(form, "id"), name: text(form, "name"), role: text(form, "role"), email: text(form, "email") },
      }).then(() => undefined),
    ["/people"],
  );
}
