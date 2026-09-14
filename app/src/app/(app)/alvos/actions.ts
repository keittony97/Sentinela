"use server";

import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";
import { friendlyDbError } from "@/lib/supabase/errors";

export type TargetFormState = { error: string | null };

export async function createTarget(
  _prevState: TargetFormState,
  formData: FormData,
): Promise<TargetFormState> {
  const name = String(formData.get("name") ?? "").trim();
  const url = String(formData.get("url") ?? "").trim();
  const scope = String(formData.get("scope") ?? "");
  const assetOwner = String(formData.get("asset_owner") ?? "").trim();

  if (!name || !url) {
    return { error: "Preencha nome e URL do alvo." };
  }
  if (scope !== "intranet" && scope !== "internet") {
    return { error: "Selecione o escopo (intranet ou internet)." };
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

  const { data: target, error } = await supabase
    .from("targets")
    .insert({
      organization_id: profile.organization_id,
      name,
      url,
      scope: scope as "intranet" | "internet",
      asset_owner: assetOwner || null,
      created_by: user.id,
    })
    .select("id")
    .single();

  if (error || !target) {
    return { error: friendlyDbError(error?.message ?? "Falha ao criar o alvo.") };
  }

  redirect(`/alvos/${target.id}`);
}
