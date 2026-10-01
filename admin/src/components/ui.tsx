export function PageTitle({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="mb-6">
      <h1 className="text-2xl font-semibold">{title}</h1>
      {children && <p className="mt-1 text-sm text-zinc-500">{children}</p>}
    </div>
  );
}

export function Card({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <section className="mb-6 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
      {title && <h2 className="mb-3 font-medium">{title}</h2>}
      {children}
    </section>
  );
}

export function Badge({ children, tone = "zinc" }: { children: React.ReactNode; tone?: "zinc" | "red" | "amber" | "green" }) {
  const tones = {
    zinc: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
    red: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
    amber: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
    green: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  };
  return <span className={`rounded px-1.5 py-0.5 text-xs ${tones[tone]}`}>{children}</span>;
}

export const input =
  "rounded-md border border-zinc-300 bg-transparent px-2 py-1.5 text-sm dark:border-zinc-700";

export function when(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: process.env.PACT_ADMIN_TIMEZONE ?? "UTC" });
}

export function Table({ head, children }: { head: string[]; children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-zinc-500">
          <tr>
            {head.map((h) => (
              <th key={h} className="border-b border-zinc-200 py-2 pr-4 font-normal dark:border-zinc-800">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="[&_td]:border-b [&_td]:border-zinc-100 [&_td]:py-2 [&_td]:pr-4 [&_td]:align-top dark:[&_td]:border-zinc-900">
          {children}
        </tbody>
      </table>
    </div>
  );
}
