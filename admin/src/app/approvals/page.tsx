import Link from "next/link";
import { decideTask } from "../actions";
import { ActionForm, Submit } from "@/components/action-form";
import { Badge, Card, PageTitle, when } from "@/components/ui";
import { board, Task } from "@/lib/board";

export default async function Approvals() {
  const [pending, deferred] = await Promise.all([
    board<Task[]>("/tasks?status=auth_required"),
    board<Task[]>("/tasks?deferred=1"),
  ]);
  return (
    <>
      <PageTitle title="Approvals">Tasks whose action needs a person, and tasks an agent handed back.</PageTitle>
      <Card title={`Waiting for approval (${pending.length})`}>
        {pending.length === 0 && <p className="text-sm text-zinc-500">Nothing waiting.</p>}
        {pending.map((t) => (
          <TaskRow key={t.id} t={t}>
            <ActionForm action={decideTask} className="flex gap-2">
              <input type="hidden" name="id" value={t.id} />
              <button name="decision" value="reject" className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm dark:border-zinc-700">
                Reject
              </button>
              <button name="decision" value="approve" className="rounded-md bg-zinc-900 px-3 py-1.5 text-sm text-white dark:bg-zinc-100 dark:text-zinc-900">
                Approve
              </button>
            </ActionForm>
          </TaskRow>
        ))}
      </Card>
      <Card title={`Deferred to humans (${deferred.length})`}>
        {deferred.length === 0 && <p className="text-sm text-zinc-500">Nothing deferred.</p>}
        {deferred.map((t) => (
          <TaskRow key={t.id} t={t}>
            <p className="mb-2 text-sm">
              <span className="text-zinc-500">Reason:</span> {t.defer_reason}
              {t.needed_scope?.length ? (
                <>
                  {" "}
                  <span className="text-zinc-500">· needs</span> <code className="text-xs">{t.needed_scope.join(", ")}</code>
                </>
              ) : null}
            </p>
            <p className="mb-2 text-xs text-zinc-500">
              Issue the needed mandate on the Mandates page first if the agent should do it, then put the task back.
            </p>
            <ActionForm action={decideTask}>
              <input type="hidden" name="id" value={t.id} />
              <input type="hidden" name="decision" value="resume" />
              <Submit>Put back on the board</Submit>
            </ActionForm>
          </TaskRow>
        ))}
      </Card>
    </>
  );
}

function TaskRow({ t, children }: { t: Task; children: React.ReactNode }) {
  return (
    <div className="border-b border-zinc-100 py-3 last:border-0 dark:border-zinc-900">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <Link href={`/tasks/${t.id}`} className="font-medium hover:underline">
          {t.title}
        </Link>
        <Badge>{t.project_id}</Badge>
        <Badge tone="amber">{t.action}</Badge>
      </div>
      <p className="mb-2 text-xs text-zinc-500">
        by {t.created_by}
        {t.delegate_to ? ` → ${t.delegate_to}` : ""} · {when(t.created_at)}
      </p>
      {t.body && <p className="mb-2 text-sm whitespace-pre-wrap">{t.body}</p>}
      {children}
    </div>
  );
}
