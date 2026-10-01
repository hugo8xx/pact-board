import { issueToken, registerAgent, revokeTokens, setAgentStatus } from "../actions";
import { ActionForm, Submit } from "@/components/action-form";
import { Badge, Card, input, PageTitle, Table, when } from "@/components/ui";
import { Agent, board, Project } from "@/lib/board";

const CLIENTS = ["chat", "cowork", "code", "gemini", "runner"];

export default async function Agents() {
  const [agents, projects] = await Promise.all([board<Agent[]>("/agents"), board<Project[]>("/projects")]);
  return (
    <>
      <PageTitle title="Agents">
        Each agent has its own URL, <code>/mcp/a/&lt;id&gt;</code>. Chat and Cowork sign in with OAuth; Claude Code, hooks and the
        Runner use a token.
      </PageTitle>
      <Card>
        <Table head={["Agent", "Client", "Projects", "Owner", "Last seen", "Tokens", "Status", ""]}>
          {agents.map((a) => (
            <tr key={a.id}>
              <td className="font-medium">{a.id}</td>
              <td>
                <Badge>{a.client}</Badge>
              </td>
              <td>{a.projects.join(", ")}</td>
              <td>{a.owner}</td>
              <td className="text-zinc-500">{when(a.last_seen)}</td>
              <td className="tabular-nums">{a.live_tokens}</td>
              <td>
                <Badge tone={a.status === "active" ? "green" : a.status === "paused" ? "amber" : "red"}>{a.status}</Badge>
              </td>
              <td className="space-y-2">
                <ActionForm action={setAgentStatus} className="flex gap-2">
                  <input type="hidden" name="id" value={a.id} />
                  {a.status !== "active" && (
                    <button name="status" value="active" className="text-sm underline">
                      Resume
                    </button>
                  )}
                  {a.status === "active" && (
                    <button name="status" value="paused" className="text-sm underline">
                      Pause
                    </button>
                  )}
                  {a.status !== "banned" && (
                    <button name="status" value="banned" className="text-sm text-red-600 underline">
                      Ban
                    </button>
                  )}
                </ActionForm>
                <ActionForm action={issueToken}>
                  <input type="hidden" name="id" value={a.id} />
                  <button className="text-sm underline">New token</button>
                </ActionForm>
                {a.live_tokens > 0 && (
                  <ActionForm action={revokeTokens}>
                    <input type="hidden" name="id" value={a.id} />
                    <button className="text-sm text-red-600 underline">Revoke tokens</button>
                  </ActionForm>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </Card>

      <Card title="Register an agent">
        <ActionForm action={registerAgent} className="grid gap-3 sm:max-w-md">
          <label className="grid gap-1 text-sm">
            Id <input name="id" required pattern="[a-z0-9][a-z0-9-]{0,62}" placeholder="code-web" className={input} />
          </label>
          <label className="grid gap-1 text-sm">
            Client
            <select name="client" className={input}>
              {CLIENTS.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>
          <fieldset className="grid gap-1 text-sm">
            <legend className="mb-1">Projects (code and runner: exactly one)</legend>
            {projects.map((p) => (
              <label key={p.id} className="flex items-center gap-2">
                <input type="checkbox" name="projects" value={p.id} /> {p.id}
                {p.production && <Badge tone="red">production</Badge>}
              </label>
            ))}
          </fieldset>
          <div className="flex gap-3">
            <label className="grid gap-1 text-sm">
              Delegations <input name="delegations" type="number" min={0} max={5} defaultValue={2} className={`${input} w-24`} />
            </label>
            <label className="grid gap-1 text-sm">
              Days <input name="days" type="number" min={1} max={365} defaultValue={30} className={`${input} w-24`} />
            </label>
          </div>
          <div>
            <Submit tone="primary">Register</Submit>
          </div>
        </ActionForm>
      </Card>
    </>
  );
}
