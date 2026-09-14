import { NextResponse } from "next/server";
import { renderToBuffer } from "@react-pdf/renderer";
import { createClient } from "@/lib/supabase/server";
import { ProjectReportDocument } from "@/lib/pdf/ProjectReportDocument";
import { buildProjectReportData } from "@/lib/pdf/buildProjectReportData";

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

  const report = await buildProjectReportData(supabase, id, projectId, user.id);
  if (!report) {
    return NextResponse.json({ error: "Projeto ou alvo não encontrado." }, { status: 404 });
  }

  const buffer = await renderToBuffer(ProjectReportDocument(report.props));

  const filename = `sentinela-relatorio-${report.targetName}-${report.projectName}`
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
