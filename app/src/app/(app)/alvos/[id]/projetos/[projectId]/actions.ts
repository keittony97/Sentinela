"use server";

import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { friendlyDbError } from "@/lib/supabase/errors";

export type ScanFormState = { error: string | null };

// Só a ferramenta passiva "headers_tls" existe até a Fase 5 — nenhuma
// ferramenta ativa é oferecida aqui, então is_active_tool sempre false e o
// gate de modalidade legal (Fase 2) nem entra em jogo por enquanto.
export async function startScan(
  _prevState: ScanFormState,
  formData: FormData,
): Promise<ScanFormState> {
  const targetId = String(formData.get("target_id") ?? "");
  const projectId = String(formData.get("project_id") ?? "");
  if (!targetId || !projectId) {
    return { error: "Projeto inválido." };
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
      tools_used: ["headers_tls"],
      triggered_by: user.id,
    })
    .select("id")
    .single();

  if (error || !scan) {
    return { error: friendlyDbError(error?.message ?? "Falha ao iniciar o scan.") };
  }

  redirect(`/alvos/${targetId}/projetos/${projectId}/scans/${scan.id}`);
}
