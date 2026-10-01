import { addProject, setProjectFlag } from "../actions";
import { ActionForm, Submit } from "@/components/action-form";
import { Badge, Card, input, PageTitle, Table } from "@/components/ui";
import { board, Project } from "@/lib/board";

export default async function Projects() {
  const projects = await board<Project[]>("/projects");
  return (
    <>
      <PageTitle title="Projects">Production projects are off-limits to Runners. A frozen project refuses every agent.</PageTitle>
      <Card>
        <Table head={["Project", "Name", "Open tasks", "Production", "Frozen"]}>
          {projects.map((p) => (
            <tr key={p.id}>
              <td className="font-medium">{p.id}</td>
              <td>{p.name}</td>
              <td className="tabular-nums">{p.open_tasks}</td>
              <td>
                <Toggle id={p.id} flag="production" on={p.production} />
              </td>
              <td>
                <Toggle id={p.id} flag="frozen" on={p.frozen} />
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card title="New project">
        <ActionForm action={addProject} className="flex flex-wrap items-end gap-3">
          <label className="grid gap-1 text-sm">
            Id <input name="id" required pattern="[a-z0-9][a-z0-9-]{0,62}" className={input} />
          </label>
          <label className="grid gap-1 text-sm">
            Name <input name="name" required className={input} />
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" name="production" /> Production
          </label>
          <Submit tone="primary">Create</Submit>
        </ActionForm>
      </Card>
    </>
  );
}

function Toggle({ id, flag, on }: { id: string; flag: string; on: boolean }) {
  return (
    <ActionForm action={setProjectFlag} className="flex items-center gap-2">
      <input type="hidden" name="id" value={id} />
      <input type="hidden" name="flag" value={flag} />
      <input type="hidden" name="value" value={on ? "false" : "true"} />
      {on ? <Badge tone="red">yes</Badge> : <Badge>no</Badge>}
      <button className="text-sm underline">{on ? "Turn off" : "Turn on"}</button>
    </ActionForm>
  );
}
