import Link from "next/link";
import { notFound } from "next/navigation";
import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { ScopeBadge } from "@/components/terminal/ScopeBadge";
import { LegalModeBadge } from "@/components/terminal/LegalModeBadge";
import { createClient } from "@/lib/supabase/server";

export default async function TargetDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const supabase = await createClient();

  const { data: target } = await supabase.from("targets").select("*").eq("id", id).single();
  if (!target) notFound();

  const { data: projects } = await supabase
    .from("projects")
    .select("id, name, auth_mode, legal_mode, status, created_at")
    .eq("target_id", id)
    .order("created_at", { ascending: false });

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TerminalPrompt path={`~/alvos/${target.name}`} className="text-lg" />
        <Link
          href={`/alvos/${id}/projetos/novo`}
          className="border border-[var(--color-border-bright)] px-3 py-1.5 text-sm text-[var(--color-phosphor)] hover:bg-[var(--color-phosphor)] hover:text-black"
        >
          + novo projeto
        </Link>
      </div>

      <TerminalWindow title={`user@sentinela:~/alvos/${target.name}$`} accent="cyan">
        <dl className="flex flex-col gap-1 text-sm">
          <div className="flex gap-2">
            <dt className="text-[var(--color-fg-dim)]">url:</dt>
            <dd>{target.url}</dd>
          </div>
          <div className="flex items-center gap-2">
            <dt className="text-[var(--color-fg-dim)]">escopo:</dt>
            <dd>
              <ScopeBadge scope={target.scope} />
            </dd>
          </div>
          {target.asset_owner && (
            <div className="flex gap-2">
              <dt className="text-[var(--color-fg-dim)]">dono do ativo:</dt>
              <dd>{target.asset_owner}</dd>
            </div>
          )}
        </dl>
      </TerminalWindow>

      <TerminalWindow title={`user@sentinela:~/alvos/${target.name}/projetos$`} accent="amber">
        {projects && projects.length > 0 ? (
          <ul className="flex flex-col gap-3 text-sm">
            {projects.map((project) => (
              <li
                key={project.id}
                className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--color-border)] pb-3 last:border-none last:pb-0"
              >
                <span className="flex flex-col">
                  <span>{project.name}</span>
                  <span className="text-xs text-[var(--color-fg-muted)]">
                    {project.auth_mode === "com_login" ? "com login" : "sem login"} · {project.status}
                  </span>
                </span>
                <LegalModeBadge mode={project.legal_mode} />
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-[var(--color-fg-dim)]">
            Nenhum projeto ainda. Todo projeto declara a modalidade legal antes de rodar
            qualquer verificação.
          </p>
        )}
      </TerminalWindow>
    </div>
  );
}
