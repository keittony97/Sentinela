"use server";

import { revalidatePath } from "next/cache";
import { createClient } from "@/lib/supabase/server";
import { friendlyDbError } from "@/lib/supabase/errors";

export type OrganizationFormState = { error: string | null; success: boolean };

export async function updateOrganization(
  _prevState: OrganizationFormState,
  formData: FormData,
): Promise<OrganizationFormState> {
  const name = String(formData.get("name") ?? "").trim();
  const contactEmail = String(formData.get("contact_email") ?? "").trim();

  if (!name) {
    return { error: "Informe o nome da organização.", success: false };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return { error: "Sessão expirada — faça login novamente.", success: false };
  }

  const { data: profile } = await supabase
    .from("users")
    .select("organization_id")
    .eq("id", user.id)
    .single();
  if (!profile) return { error: "Perfil não encontrado.", success: false };

  const { error } = await supabase
    .from("organizations")
    .update({ name, contact_email: contactEmail || null })
    .eq("id", profile.organization_id);

  if (error) {
    return { error: friendlyDbError(error.message), success: false };
  }

  revalidatePath("/", "layout");
  return { error: null, success: true };
}
