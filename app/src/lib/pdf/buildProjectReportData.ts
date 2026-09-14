import type { createClient } from "@/lib/supabase/server";
import { findingsInvolvePersonalData } from "./personalDataDetection";
import type { ProjectReportProps } from "./ProjectReportDocument";

type SupabaseServerClient = Awaited<ReturnType<typeof createClient>>;

/**
 * Monta os dados de um relatório PDF (props de ProjectReportDocument).
 * Sem `scanId`: agrega todos os scans do projeto (relatório do projeto).
 * Com `scanId`: restringe a um único scan (relatório de uma verificação).
 */
export async function buildProjectReportData(
  supabase: SupabaseServerClient,
  targetId: string,
  projectId: string,
  userId: string,
  scanId?: string,
): Promise<{ props: ProjectReportProps; targetName: string; projectName: string } | null> {
  const [{ data: project }, { data: target }, { data: profile }] = await Promise.all([
    supabase.from("projects").select("*").eq("id", projectId).single(),
    supabase.from("targets").select("*").eq("id", targetId).single(),
    supabase.from("users").select("organization_id").eq("id", userId).single(),
  ]);

  if (!project || !target || !profile) return null;

  const [{ data: organization }, { data: complianceTemplate }] = await Promise.all([
    supabase.from("organizations").select("name").eq("id", profile.organization_id).single(),
    supabase
      .from("report_compliance_templates")
      .select("methodology_statement, lgpd_note")
      .eq("organization_id", profile.organization_id)
      .maybeSingle(),
  ]);

  let scansQuery = supabase
    .from("scans")
    .select("id, tools_used, status, created_at, started_at, finished_at, triggered_by")
    .eq("project_id", projectId)
    .order("created_at", { ascending: true });
  if (scanId) scansQuery = scansQuery.eq("id", scanId);
  const { data: scans } = await scansQuery;

  if (scanId && (!scans || scans.length === 0)) return null;

  // Responsável técnico por scan — busca separada em vez de embedding do
  // PostgREST, mais explícito.
  const triggeredByIds = Array.from(
    new Set((scans ?? []).map((s) => s.triggered_by).filter((v): v is string => Boolean(v))),
  );
  const { data: triggeredByUsers } =
    triggeredByIds.length > 0
      ? await supabase.from("users").select("id, username, role").in("id", triggeredByIds)
      : { data: [] };
  const userById = new Map((triggeredByUsers ?? []).map((u) => [u.id, u]));

  const scansWithResponsible = (scans ?? []).map((scan) => ({
    ...scan,
    triggered_by_username: userById.get(scan.triggered_by)?.username ?? null,
    triggered_by_role: userById.get(scan.triggered_by)?.role ?? null,
  }));

  const scanIds = (scans ?? []).map((s) => s.id);

  const { data: findings } =
    scanIds.length > 0
      ? await supabase.from("findings").select("*").in("scan_id", scanIds)
      : { data: [] };

  return {
    targetName: target.name,
    projectName: project.name,
    props: {
      organizationName: organization?.name ?? "org",
      target: { name: target.name, url: target.url, scope: target.scope },
      project: {
        name: project.name,
        auth_mode: project.auth_mode,
        legal_mode: project.legal_mode,
        authorization_reference: project.authorization_reference,
        authorization_justification: project.authorization_justification,
        created_at: project.created_at,
      },
      scans: scansWithResponsible,
      findings: findings ?? [],
      generatedAt: new Date().toLocaleString("pt-BR"),
      complianceTemplate: complianceTemplate ?? null,
      involvesPersonalData: findingsInvolvePersonalData(findings ?? []),
    },
  };
}
