import { addHuman } from "../actions";
import { ActionForm, Submit } from "@/components/action-form";
import { Badge, Card, input, PageTitle, Table } from "@/components/ui";
import { board } from "@/lib/board";

type Human = { id: string; name: string; role: string; email: string | null };

export default async function People() {
  const people = await board<Human[]>("/humans");
  return (
    <>
      <PageTitle title="People">
        Owners do everything, including the kill switch. Approvers approve tasks and issue mandates. Viewers read.
      </PageTitle>
      <Card>
        <Table head={["Id", "Name", "Email", "Role"]}>
          {people.map((p) => (
            <tr key={p.id}>
              <td className="font-medium">{p.id}</td>
              <td>{p.name}</td>
              <td>{p.email ?? "—"}</td>
              <td>
                <Badge>{p.role}</Badge>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card title="Add a person">
        <p className="mb-3 text-sm text-zinc-500">
          They also need an account on the sign-in server with the same email.
        </p>
        <ActionForm action={addHuman} className="flex flex-wrap items-end gap-3">
          <input name="id" required placeholder="id" pattern="[a-z0-9][a-z0-9-]{0,62}" className={input} />
          <input name="name" required placeholder="name" className={input} />
          <input name="email" type="email" required placeholder="email" className={input} />
          <select name="role" className={input}>
            <option>viewer</option>
            <option>approver</option>
            <option>owner</option>
          </select>
          <Submit tone="primary">Add</Submit>
        </ActionForm>
      </Card>
    </>
  );
}
