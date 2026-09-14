"use server";

import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { friendlyDbError } from "@/lib/supabase/errors";
import { PASSIVE_TOOL_IDS } from "@/lib/scanTools";

export type ScanFormState = { error: string | null };

// Todas as ferramentas aqui são passivas (is_active_tool sempre false) —
// nenhuma ferramenta ativa é oferecida nesta tela, então o gate de
// modalidade legal (Fase 2) nem entra em jogo por enquanto.
export async function startScan(
  _prevState: ScanFormState,
  formData: FormData,
): Promise<ScanFormState> {
  const targetId = String(formData.get("target_id") ?? "");
  const projectId = String(formData.get("project_id") ?? "");
  const tools = formData.getAll("tools").map(String).filter((t) => PASSIVE_TOOL_IDS.includes(t));

  if (!targetId || !projectId) {
    return { error: "Projeto inválido." };
  }
  if (tools.length === 0) {
    return { error: "Selecione ao menos uma ferramenta." };
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

  const { data: scan, error } = await supabase
    .from("scans")
    .insert({
      organization_id: profile.organization_id,
      project_id: projectId,
      is_active_tool: false,
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
