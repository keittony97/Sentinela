import { NextResponse } from "next/server";
import { renderToBuffer } from "@react-pdf/renderer";
import { createClient } from "@/lib/supabase/server";
import { ProjectReportDocument } from "@/lib/pdf/ProjectReportDocument";
import { findingsInvolvePersonalData } from "@/lib/pdf/personalDataDetection";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string; projectId: string }> },
) {
  const { id, projectId } = await params;
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Não autenticado." }, { status: 401 });
  }

  const [{ data: project }, { data: target }, { data: profile }] = await Promise.all([
    supabase.from("projects").select("*").eq("id", projectId).single(),
    supabase.from("targets").select("*").eq("id", id).single(),
    supabase.from("users").select("organization_id").eq("id", user.id).single(),
  ]);

  if (!project || !target || !profile) {
    return NextResponse.json({ error: "Projeto ou alvo não encontrado." }, { status: 404 });
  }

  const [{ data: organization }, { data: complianceTemplate }] = await Promise.all([
    supabase.from("organizations").select("name").eq("id", profile.organization_id).single(),
    supabase
      .from("report_compliance_templates")
      .select("methodology_statement, lgpd_note")
      .eq("organization_id", profile.organization_id)
      .maybeSingle(),
  ]);

  const { data: scans } = await supabase
    .from("scans")
    .select("id, tools_used, status, created_at, started_at, finished_at, triggered_by")
    .eq("project_id", projectId)
    .order("created_at", { ascending: true });

  // Responsável técnico por scan (Fase 6+: cabeçalho de conformidade) —
  // busca separada em vez de embedding do PostgREST, mais explícito.
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

  const buffer = await renderToBuffer(
    ProjectReportDocument({
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
    }),
  );

  const filename = `sentinela-relatorio-${target.name}-${project.name}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");

  return new NextResponse(new Uint8Array(buffer), {
    headers: {
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="${filename}.pdf"`,
    },
  });
}
