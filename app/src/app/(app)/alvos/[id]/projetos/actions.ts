"use server";

import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { friendlyDbError } from "@/lib/supabase/errors";

export type ProjectFormState = { error: string | null };

export async function createProject(
  _prevState: ProjectFormState,
  formData: FormData,
): Promise<ProjectFormState> {
  const targetId = String(formData.get("target_id") ?? "");
  const name = String(formData.get("name") ?? "").trim();
  const authMode = String(formData.get("auth_mode") ?? "");
  const legalMode = String(formData.get("legal_mode") ?? "");
  const authorizationConfirmed = formData.get("authorization_confirmed") === "on";
  const authorizationReference = String(formData.get("authorization_reference") ?? "").trim();
  const authorizationJustification = String(
    formData.get("authorization_justification") ?? "",
  ).trim();

  if (!targetId || !name) {
    return { error: "Preencha o nome do projeto." };
  }
  if (authMode !== "sem_login" && authMode !== "com_login") {
    return { error: "Selecione o modo de autenticação do alvo." };
  }
  if (legalMode !== "verificacao_externa" && legalMode !== "ambiente_teste") {
    return { error: "Selecione a modalidade legal." };
  }
  if (legalMode === "ambiente_teste") {
    if (!authorizationConfirmed) {
      return {
        error:
          'A modalidade "Ambiente de Teste" exige confirmar que o alvo é de propriedade da empresa ou está formalmente autorizado.',
      };
    }
    if (!authorizationJustification) {
      return { error: "Informe a justificativa ou nº do termo de autorização." };
    }
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

  const { data: project, error } = await supabase
    .from("projects")
    .insert({
      organization_id: profile.organization_id,
      target_id: targetId,
      name,
      auth_mode: authMode as "sem_login" | "com_login",
      legal_mode: legalMode as "verificacao_externa" | "ambiente_teste",
      authorization_confirmed: legalMode === "ambiente_teste" ? authorizationConfirmed : false,
      authorization_reference: authorizationReference || null,
      authorization_justification: authorizationJustification || null,
      created_by: user.id,
    })
    .select("id")
    .single();

  if (error || !project) {
    return { error: friendlyDbError(error?.message ?? "Falha ao criar o projeto.") };
  }

  redirect(`/alvos/${targetId}`);
}
