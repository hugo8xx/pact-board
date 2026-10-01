import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";
import { currentSession } from "@/lib/board";

export const metadata: Metadata = { title: "PACT Admin", robots: { index: false, follow: false } };

const NAV = [
  ["/", "Overview"],
  ["/approvals", "Approvals"],
  ["/agents", "Agents"],
  ["/projects", "Projects"],
  ["/mandates", "Mandates"],
  ["/audit", "Audit log"],
  ["/people", "People"],
] as const;

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const session = await currentSession();
  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-zinc-900 antialiased dark:bg-zinc-950 dark:text-zinc-100">
        {session && (
          <header className="border-b border-zinc-200 dark:border-zinc-800">
            <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
              <span className="font-semibold tracking-wide">PACT</span>
              <nav className="flex flex-wrap gap-4 text-sm text-zinc-600 dark:text-zinc-400">
                {NAV.map(([href, label]) => (
                  <Link key={href} href={href} className="hover:text-zinc-900 dark:hover:text-zinc-100">
                    {label}
                  </Link>
                ))}
              </nav>
              <form action="/auth/logout" method="post" className="ml-auto flex items-center gap-3 text-sm">
                <span className="text-zinc-500">{session.user.email}</span>
                <button className="text-zinc-600 underline-offset-2 hover:underline dark:text-zinc-400">Sign out</button>
              </form>
            </div>
          </header>
        )}
        <main className="mx-auto max-w-6xl px-4 py-8">{children}</main>
      </body>
    </html>
  );
}
