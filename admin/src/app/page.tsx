import Link from "next/link";
import { setKillSwitch } from "./actions";
import { ActionForm, Submit } from "@/components/action-form";
import { Badge, Card, input, PageTitle, Table, when } from "@/components/ui";
import { board, Me, Overview } from "@/lib/board";

export default async function OverviewPage() {
  const [o, me] = await Promise.all([board<Overview>("/overview"), board<Me>("/me")]);
  const projects = [...new Set(o.tasks.map((t) => t.project_id))];
  const statuses = ["submitted", "working", "auth_required", "input_required", "completed", "failed", "canceled"];
  return (
    <>
      <PageTitle title="Overview">Signed in as {me.name} ({me.role})</PageTitle>

      <Card title="Kill switch">
        {o.halted ? (
          <div className="flex flex-wrap items-center gap-4">
            <Badge tone="red">ON — every agent call is refused</Badge>
            {me.role === "owner" && (
              <ActionForm action={setKillSwitch}>
                <input type="hidden" name="halted" value="false" />
                <Submit tone="primary">Turn off</Submit>
              </ActionForm>
            )}
          </div>
        ) : me.role === "owner" ? (
          <ActionForm action={setKillSwitch} className="flex flex-wrap items-center gap-3">
            <input type="hidden" name="halted" value="true" />
            <input name="confirm" placeholder="Type HALT" className={input} autoComplete="off" />
            <Submit tone="danger">Stop every agent</Submit>
          </ActionForm>
        ) : (
          <p className="text-sm text-zinc-500">Off. Only owners can turn it on.</p>
        )}
      </Card>

      <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Waiting for approval" value={o.pending_approvals} href="/approvals" alert={o.pending_approvals > 0} />
        <Stat label="Deferred to humans" value={o.deferred} href="/approvals" alert={o.deferred > 0} />
        <Stat label="Active agents" value={o.agents_by_status.active ?? 0} href="/agents" />
        <Stat label="Paused or banned" value={(o.agents_by_status.paused ?? 0) + (o.agents_by_status.banned ?? 0)} href="/agents" />
      </div>

      <Card title="Tasks by project (open, and closed in the last 7 days)">
        {projects.length === 0 ? (
          <p className="text-sm text-zinc-500">No tasks yet.</p>
        ) : (
          <Table head={["Project", ...statuses]}>
            {projects.map((p) => (
              <tr key={p}>
                <td className="font-medium">{p}</td>
                {statuses.map((s) => (
                  <td key={s} className="tabular-nums">
                    {o.tasks.find((t) => t.project_id === p && t.status === s)?.n ?? ""}
                  </td>
                ))}
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="Agents seen in the last hour">
        {o.active_agents.length === 0 ? (
          <p className="text-sm text-zinc-500">None.</p>
        ) : (
          <ul className="text-sm">
            {o.active_agents.map((a) => (
              <li key={a.id} className="flex justify-between border-b border-zinc-100 py-1.5 dark:border-zinc-900">
                <span>
                  {a.id} <Badge>{a.client}</Badge>
                </span>
                <span className="text-zinc-500">{when(a.last_seen)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

function Stat({ label, value, href, alert }: { label: string; value: number; href: string; alert?: boolean }) {
  return (
    <Link href={href} className="rounded-lg border border-zinc-200 p-4 hover:bg-zinc-50 dark:border-zinc-800 dark:hover:bg-zinc-900">
      <div className={`text-2xl font-semibold tabular-nums ${alert ? "text-amber-600" : ""}`}>{value}</div>
      <div className="text-sm text-zinc-500">{label}</div>
    </Link>
  );
}
