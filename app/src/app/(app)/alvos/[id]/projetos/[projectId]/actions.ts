"use server";

import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { friendlyDbError } from "@/lib/supabase/errors";
import { ACTIVE_TOOL_IDS, EXPLOITATION_TOOL_IDS, PASSIVE_TOOL_IDS } from "@/lib/scanTools";

export type ScanFormState = { error: string | null };

export async function startScan(
  _prevState: ScanFormState,
  formData: FormData,
): Promise<ScanFormState> {
  const targetId = String(formData.get("target_id") ?? "");
  const projectId = String(formData.get("project_id") ?? "");
  const selected = formData.getAll("tools").map(String);
  const tools = selected.filter(
    (t) => PASSIVE_TOOL_IDS.includes(t) || ACTIVE_TOOL_IDS.includes(t) || EXPLOITATION_TOOL_IDS.includes(t),
  );
  const isActiveTool = tools.some((t) => ACTIVE_TOOL_IDS.includes(t) || EXPLOITATION_TOOL_IDS.includes(t));
  const isExploitationTool = tools.some((t) => EXPLOITATION_TOOL_IDS.includes(t));
  const exploitationConfirmed = formData.get("exploitation_confirmed") === "on";
  const exploitationJustification = String(formData.get("exploitation_justification") ?? "").trim();

  if (!targetId || !projectId) {
    return { error: "Projeto inválido." };
  }
  if (tools.length === 0) {
    return { error: "Selecione ao menos uma ferramenta." };
  }
  if (isExploitationTool && (!exploitationConfirmed || !exploitationJustification)) {
    return {
      error:
        'Ferramentas de "Exploração Confirmatória" exigem a confirmação explícita e a justificativa separadas.',
    };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: profile } = await supabase
    .from("users")
    .select("organization_id")
    .eq("id", user.id)
    .single();
  if (!profile) return { error: "Perfil não encontrado." };

  // A validação de verdade (modalidade legal, autorização, role admin
  // pra ferramenta ativa) é reforçada pelo trigger enforce_scan_legal_mode
  // no banco — isso aqui só existe pra dar um erro amigável em vez do
  // erro cru do Postgres, caso alguém tente contornar a UI.
  const { data: scan, error } = await supabase
    .from("scans")
    .insert({
      organization_id: profile.organization_id,
      project_id: projectId,
      is_active_tool: isActiveTool,
      is_exploitation_tool: isExploitationTool,
      exploitation_confirmed: isExploitationTool ? exploitationConfirmed : false,
      exploitation_justification: isExploitationTool ? exploitationJustification : null,
      tools_used: tools,
      triggered_by: user.id,
    })
    .select("id")
    .single();

  if (error || !scan) {
    return { error: friendlyDbError(error?.message ?? "Falha ao iniciar o scan.") };
  }

  redirect(`/alvos/${targetId}/projetos/${projectId}/scans/${scan.id}`);
}
