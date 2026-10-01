"use client";

import { useActionState } from "react";
import type { ActionState } from "@/app/actions";

type Props = {
  action: (state: ActionState, form: FormData) => Promise<ActionState>;
  children: React.ReactNode;
  className?: string;
};

/** A form bound to a server action, showing its result (and a one-time secret) underneath. */
export function ActionForm({ action, children, className }: Props) {
  const [state, formAction, pending] = useActionState(action, null);
  return (
    <form action={formAction} className={className}>
      <fieldset disabled={pending} className="contents">
        {children}
      </fieldset>
      {state?.error && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{state.error}</p>}
      {state?.ok && <p className="mt-2 text-sm text-emerald-700 dark:text-emerald-400">{state.ok}</p>}
      {state?.secret && (
        <div className="mt-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs dark:border-amber-700 dark:bg-amber-950">
          <p className="mb-1 font-medium">Copy it now — it is not shown again.</p>
          <code className="break-all select-all">{state.secret}</code>
        </div>
      )}
    </form>
  );
}

export function Submit({ children, tone = "default" }: { children: React.ReactNode; tone?: "default" | "primary" | "danger" }) {
  const tones = {
    default: "border-zinc-300 hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800",
    primary: "border-zinc-900 bg-zinc-900 text-white hover:bg-zinc-700 dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900",
    danger: "border-red-600 bg-red-600 text-white hover:bg-red-700",
  };
  return (
    <button type="submit" className={`rounded-md border px-3 py-1.5 text-sm disabled:opacity-50 ${tones[tone]}`}>
      {children}
    </button>
  );
}
