import { Badge, Card, PageTitle, when } from "@/components/ui";
import { board, Trace } from "@/lib/board";

/** One task: what happened to it, and for each step the chain of authority back to a person. */
export default async function TaskTrace({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { task, entries, mandates } = await board<Trace>(`/tasks/${id}`);
  const byId = new Map(mandates.map((m) => [m.id, m]));
  return (
    <>
      <PageTitle title={task.title}>
        {task.project_id} · {task.action} · created by {task.created_by}
        {task.delegate_to ? ` for ${task.delegate_to}` : ""}
      </PageTitle>
      <div className="mb-6 flex flex-wrap gap-2">
        <Badge tone={task.status === "completed" ? "green" : task.status === "failed" || task.status === "canceled" ? "red" : "amber"}>
          {task.status}
        </Badge>
        {task.assignee && <Badge>held by {task.assignee}</Badge>}
        {task.approved_by && <Badge>approved by {task.approved_by}</Badge>}
      </div>
      {task.body && (
        <Card title="Task">
          <p className="text-sm whitespace-pre-wrap">{task.body}</p>
        </Card>
      )}
      {task.result != null && (
        <Card title="Result">
          <pre className="overflow-x-auto text-xs whitespace-pre-wrap">{JSON.stringify(task.result, null, 2)}</pre>
        </Card>
      )}
      <Card title="Timeline">
        <ol className="space-y-4">
          {entries.map((e) => (
            <li key={e.id} className="text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-zinc-500">{when(e.at)}</span>
                <span className="font-medium">{e.agent_id ?? e.actor}</span>
                <code className="text-xs">{e.action}</code>
                <Badge tone={e.outcome === "ok" ? "green" : "red"}>{e.outcome}</Badge>
              </div>
              {e.mandate_chain.length > 0 && (
                <div className="mt-1 flex flex-wrap items-center gap-1 text-xs text-zinc-500">
                  {e.mandate_chain.map((mid, i) => {
                    const m = byId.get(mid);
                    return (
                      <span key={mid}>
                        {i === 0 && m?.issuer_kind === "human" && <>👤 {m.issuer} → </>}
                        <span className={m?.revoked_at ? "line-through" : ""}>{m?.holder ?? mid.slice(0, 8)}</span>
                        {i < e.mandate_chain.length - 1 && " → "}
                      </span>
                    );
                  })}
                </div>
              )}
            </li>
          ))}
        </ol>
      </Card>
    </>
  );
}
