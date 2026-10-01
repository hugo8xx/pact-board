import Link from "next/link";
import { Badge, Card, input, PageTitle, Table, when } from "@/components/ui";
import { board, Entry } from "@/lib/board";

type Filters = { agent?: string; project?: string; refused?: string; before?: string };

export default async function Audit({ searchParams }: { searchParams: Promise<Filters> }) {
  const f = await searchParams;
  const query = new URLSearchParams(Object.entries(f).filter(([, v]) => v) as [string, string][]);
  query.set("limit", "100");
  const [entries, verdicts] = await Promise.all([
    board<Entry[]>(`/entries?${query}`),
    board<{ chain_key: string; ok: boolean; checked: number }[]>("/log/verify"),
  ]);
  const older = entries.at(-1)?.id;
  return (
    <>
      <PageTitle title="Audit log">
        Every call, including refused ones. Entries cannot be changed; each project&apos;s log is a hash chain.
      </PageTitle>
      <div className="mb-4 flex flex-wrap gap-2 text-sm">
        {verdicts.map((v) => (
          <Badge key={v.chain_key} tone={v.ok ? "green" : "red"}>
            {v.chain_key}: {v.ok ? `intact (${v.checked})` : "BROKEN"}
          </Badge>
        ))}
      </div>
      <form className="mb-4 flex flex-wrap items-end gap-3">
        <input name="agent" defaultValue={f.agent} placeholder="agent" className={input} />
        <input name="project" defaultValue={f.project} placeholder="project" className={input} />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" name="refused" value="1" defaultChecked={f.refused === "1"} /> Refused only
        </label>
        <button className="rounded-md border border-zinc-300 px-3 py-1.5 text-sm dark:border-zinc-700">Filter</button>
      </form>
      <Card>
        <Table head={["When", "Who", "Action", "Outcome", "Project", "Task", "Payload"]}>
          {entries.map((e) => (
            <tr key={e.id}>
              <td className="whitespace-nowrap text-zinc-500">{when(e.at)}</td>
              <td>{e.agent_id ?? e.actor}</td>
              <td>
                <code className="text-xs">{e.action}</code>
              </td>
              <td>
                <Badge tone={e.outcome === "ok" ? "green" : "red"}>{e.outcome}</Badge>
              </td>
              <td>{e.project_id ?? "—"}</td>
              <td>
                {e.task_id ? (
                  <Link href={`/tasks/${e.task_id}`} className="underline">
                    trace
                  </Link>
                ) : (
                  "—"
                )}
              </td>
              <td className="max-w-xs">
                {e.payload_erased ? (
                  <Badge>erased</Badge>
                ) : (
                  <code className="block truncate text-xs text-zinc-500" title={JSON.stringify(e.payload)}>
                    {JSON.stringify(e.payload)}
                  </code>
                )}
              </td>
            </tr>
          ))}
        </Table>
        {older && entries.length === 100 && (
          <p className="mt-3 text-sm">
            <Link href={`/audit?${new URLSearchParams({ ...f, before: String(older) } as Record<string, string>)}`} className="underline">
              Older →
            </Link>
          </p>
        )}
      </Card>
    </>
  );
}
