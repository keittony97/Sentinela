import Link from "next/link";
import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { ScopeBadge } from "@/components/terminal/ScopeBadge";
import { requireUser, canWrite } from "@/lib/supabase/auth";
import { createClient } from "@/lib/supabase/server";

export default async function DashboardPage() {
  const session = await requireUser();
  const supabase = await createClient();

  const { data: targets } = await supabase
    .from("targets")
    .select("id, name, url, scope, created_at")
    .order("created_at", { ascending: false })
    .limit(5);

  const { count: targetCount } = await supabase
    .from("targets")
    .select("id", { count: "exact", head: true });

  const { count: projectCount } = await supabase
    .from("projects")
    .select("id", { count: "exact", head: true });

  return (
    <div className="flex flex-1 flex-col gap-6">
      <div className="flex flex-col gap-1">
        <TerminalPrompt path="~" className="text-lg" />
        <p className="text-sm text-[var(--color-fg-dim)]">
          {targetCount ?? 0} alvo(s) cadastrado(s) · {projectCount ?? 0} projeto(s)
        </p>
      </div>

      {!canWrite(session) && (
        <div className="border border-[var(--color-amber)] bg-[var(--color-bg-elevated)] px-4 py-3 text-sm text-[var(--color-amber)]">
          [AVISO] Sua conta ({session.profile.role}) precisa de MFA habilitado para cadastrar
          alvos ou projetos.{" "}
          <Link href="/mfa" className="underline">
            Habilitar agora »
          </Link>
        </div>
      )}

      <TerminalWindow title="user@sentinela:~/alvos$" accent="phosphor">
        {targets && targets.length > 0 ? (
          <ul className="flex flex-col gap-3 text-sm">
            {targets.map((target) => (
              <li key={target.id}>
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
          <p className="text-sm text-[var(--color-fg-dim)]">
            Nenhum alvo cadastrado ainda.
          </p>
        )}

        <div className="mt-4 border-t border-[var(--color-border)] pt-4">
          <Link
            href="/alvos/novo"
            className="text-sm text-[var(--color-phosphor)] hover:underline"
          >
            + novo alvo
          </Link>
        </div>
      </TerminalWindow>
    </div>
  );
}
