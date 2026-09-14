import { NextResponse } from "next/server";
import { renderToBuffer } from "@react-pdf/renderer";
import { createClient } from "@/lib/supabase/server";
import { ProjectReportDocument } from "@/lib/pdf/ProjectReportDocument";

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

  const { data: organization } = await supabase
    .from("organizations")
    .select("name")
    .eq("id", profile.organization_id)
    .single();

  const { data: scans } = await supabase
    .from("scans")
    .select("id, tools_used, status, created_at, finished_at")
    .eq("project_id", projectId)
    .order("created_at", { ascending: true });

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
      scans: scans ?? [],
      findings: findings ?? [],
      generatedAt: new Date().toLocaleString("pt-BR"),
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
