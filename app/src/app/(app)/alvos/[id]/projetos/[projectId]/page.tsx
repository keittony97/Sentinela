import Link from "next/link";
import { notFound } from "next/navigation";
import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { LegalModeBadge } from "@/components/terminal/LegalModeBadge";
import { ScanStatusBadge } from "@/components/terminal/ScanStatusBadge";
import { createClient } from "@/lib/supabase/server";
import { StartScanForm } from "./StartScanForm";

export default async function ProjectDetailPage({
  params,
}: {
  params: Promise<{ id: string; projectId: string }>;
}) {
  const { id, projectId } = await params;
  const supabase = await createClient();

  const { data: project } = await supabase
    .from("projects")
    .select("*")
    .eq("id", projectId)
    .single();
  if (!project) notFound();

  const { data: target } = await supabase.from("targets").select("id, name").eq("id", id).single();
  if (!target) notFound();

  const { data: scans } = await supabase
    .from("scans")
    .select("id, status, tools_used, created_at")
    .eq("project_id", projectId)
    .order("created_at", { ascending: false });

  return (
    <div className="flex flex-1 flex-col gap-4">
      <TerminalPrompt path={`~/alvos/${target.name}/${project.name}`} className="text-lg" />

      <TerminalWindow title={`user@sentinela:~/${project.name}$`} accent="cyan">
        <dl className="flex flex-col gap-1 text-sm">
          <div className="flex items-center gap-2">
            <dt className="text-[var(--color-fg-dim)]">modalidade legal:</dt>
            <dd>
              <LegalModeBadge mode={project.legal_mode} />
            </dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-[var(--color-fg-dim)]">autenticação:</dt>
            <dd>{project.auth_mode === "com_login" ? "com login" : "sem login"}</dd>
          </div>
          {project.legal_mode === "ambiente_teste" && project.authorization_justification && (
            <div className="flex gap-2">
              <dt className="text-[var(--color-fg-dim)]">justificativa:</dt>
              <dd>{project.authorization_justification}</dd>
            </div>
          )}
        </dl>
      </TerminalWindow>

      <TerminalWindow title={`user@sentinela:~/${project.name}/scans$`} accent="amber">
        <div className="flex flex-col gap-4">
          <StartScanForm targetId={id} projectId={projectId} />

          <div className="border-t border-[var(--color-border)] pt-4">
            {scans && scans.length > 0 ? (
              <ul className="flex flex-col gap-2 text-sm">
                {scans.map((scan) => (
                  <li key={scan.id}>
                    <Link
                      href={`/alvos/${id}/projetos/${projectId}/scans/${scan.id}`}
                      className="flex flex-wrap items-center justify-between gap-2 hover:text-[var(--color-phosphor)]"
                    >
                      <span className="text-xs text-[var(--color-fg-muted)]">
                        {(scan.tools_used ?? []).join(", ")} ·{" "}
                        {new Date(scan.created_at).toLocaleString("pt-BR")}
                      </span>
                      <ScanStatusBadge status={scan.status} />
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-[var(--color-fg-dim)]">Nenhum scan rodado ainda.</p>
            )}
          </div>
        </div>
      </TerminalWindow>
    </div>
  );
}
