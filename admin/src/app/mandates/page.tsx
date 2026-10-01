import { issueMandate, revokeMandate } from "../actions";
import { ActionForm, Submit } from "@/components/action-form";
import { Badge, Card, input, PageTitle, when } from "@/components/ui";
import { Agent, board, Mandate } from "@/lib/board";

export default async function Mandates({ searchParams }: { searchParams: Promise<{ all?: string }> }) {
  const { all } = await searchParams;
  const [mandates, agents] = await Promise.all([board<Mandate[]>(`/mandates${all ? "?all=1" : ""}`), board<Agent[]>("/agents")]);
  const children = new Map<string | null, Mandate[]>();
  for (const m of mandates) children.set(m.parent_id, [...(children.get(m.parent_id) ?? []), m]);
  // A mandate whose parent is not listed (dead, when hiding dead ones) is shown as a root.
  const ids = new Set(mandates.map((m) => m.id));
  const roots = mandates.filter((m) => m.parent_id === null || !ids.has(m.parent_id));
  return (
    <>
      <PageTitle title="Mandates">
        Every chain starts with a person. Revoking a mandate kills everything under it and stops the tasks that hang on it.
      </PageTitle>
      <p className="mb-4 text-sm">
        <a href={all ? "/mandates" : "/mandates?all=1"} className="underline">
          {all ? "Hide revoked and expired" : "Show revoked and expired"}
        </a>
      </p>
      <Card>
        {roots.length === 0 && <p className="text-sm text-zinc-500">No mandates.</p>}
        {roots.map((m) => (
          <Node key={m.id} m={m} kids={children} />
        ))}
      </Card>
      <Card title="Issue a mandate">
        <ActionForm action={issueMandate} className="grid gap-3 sm:max-w-lg">
          <label className="grid gap-1 text-sm">
            Holder
            <select name="holder" className={input}>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.id} ({a.projects.join(", ")})
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-sm">
            Scope, one per line
            <textarea name="scope" rows={3} required placeholder="task.work@project:web" className={`${input} font-mono`} />
          </label>
          <div className="flex gap-3">
            <label className="grid gap-1 text-sm">
              Delegations <input name="delegations" type="number" min={0} max={5} defaultValue={1} className={`${input} w-24`} />
            </label>
            <label className="grid gap-1 text-sm">
              Days <input name="days" type="number" min={1} max={365} defaultValue={30} className={`${input} w-24`} />
            </label>
          </div>
          <div>
            <Submit tone="primary">Issue</Submit>
          </div>
        </ActionForm>
      </Card>
    </>
  );
}

function Node({ m, kids }: { m: Mandate; kids: Map<string | null, Mandate[]> }) {
  const dead = m.revoked_at ? "revoked" : new Date(m.expires_at) < new Date() ? "expired" : null;
  return (
    <div className="border-l border-zinc-200 py-2 pl-4 dark:border-zinc-800">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className={dead ? "text-zinc-400 line-through" : "font-medium"}>{m.holder}</span>
        <span className="text-zinc-500">
          from {m.issuer_kind === "human" ? "👤 " : ""}
          {m.issuer}
        </span>
        <Badge>{m.delegations_left} delegation(s) left</Badge>
        {dead ? <Badge tone="red">{dead}</Badge> : <span className="text-xs text-zinc-500">until {when(m.expires_at)}</span>}
        {!dead && (
          <ActionForm action={revokeMandate}>
            <input type="hidden" name="id" value={m.id} />
            <button className="text-xs text-red-600 underline">Revoke</button>
          </ActionForm>
        )}
      </div>
      <div className="mt-1 flex flex-wrap gap-1">
        {m.scope.map((s) => (
          <code key={s} className="rounded bg-zinc-100 px-1 text-xs dark:bg-zinc-900">
            {s}
          </code>
        ))}
        {Object.entries(m.limits).map(([k, v]) => (
          <Badge key={k} tone="amber">
            {k}: {m.usage[k] ?? 0} / {v}
          </Badge>
        ))}
      </div>
      <div className="mt-1 text-[11px] text-zinc-400">{m.id}</div>
      {(kids.get(m.id) ?? []).map((c) => (
        <Node key={c.id} m={c} kids={kids} />
      ))}
    </div>
  );
}
