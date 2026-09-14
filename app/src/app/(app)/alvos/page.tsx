import Link from "next/link";
import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { ScopeBadge } from "@/components/terminal/ScopeBadge";
import { createClient } from "@/lib/supabase/server";

export default async function TargetsPage() {
  const supabase = await createClient();
  const { data: targets } = await supabase
    .from("targets")
    .select("id, name, url, scope, created_at")
    .order("created_at", { ascending: false });

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TerminalPrompt path="~/alvos" className="text-lg" />
        <Link
          href="/alvos/novo"
          className="border border-[var(--color-border-bright)] px-3 py-1.5 text-sm text-[var(--color-phosphor)] hover:bg-[var(--color-phosphor)] hover:text-black"
        >
          + novo alvo
        </Link>
      </div>

      <TerminalWindow title="user@sentinela:~/alvos$" accent="phosphor">
        {targets && targets.length > 0 ? (
          <ul className="flex flex-col gap-3 text-sm">
            {targets.map((target) => (
              <li
                key={target.id}
                className="border-b border-[var(--color-border)] pb-3 last:border-none last:pb-0"
              >
                <Link
                  href={`/alvos/${target.id}`}
                  className="flex flex-wrap items-center justify-between gap-2 hover:text-[var(--color-phosphor)]"
                >
                  <span className="flex flex-col">
                    <span>{target.name}</span>
                    <span className="text-xs text-[var(--color-fg-muted)]">{target.url}</span>
                  </span>
                  <ScopeBadge scope={target.scope} />
                </Link>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-[var(--color-fg-dim)]">Nenhum alvo cadastrado ainda.</p>
        )}
      </TerminalWindow>
    </div>
  );
}
