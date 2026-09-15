import "server-only";

import { cache } from "react";
import { redirect } from "next/navigation";
import { createClient } from "./server";
import type { Tables } from "./database.types";

export type SessionInfo = {
  user: { id: string; email: string };
  profile: Tables<"users">;
  organizationName: string;
  mfaCurrentLevel: "aal1" | "aal2";
  mfaNextLevel: "aal1" | "aal2";
};

// Toda página autenticada chama isso primeiro. Redireciona para /login se
// não houver sessão — a RLS também protege os dados, isso é só UX.
// cache() evita repetir a chamada quando layout + page pedem a sessão no
// mesmo request.
export const requireUser = cache(async (): Promise<SessionInfo> => {
  const supabase = await createClient();

  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/login");
  }

  const { data: profile } = await supabase.from("users").select("*").eq("id", user.id).single();

  if (!profile) {
    redirect("/login");
  }

  const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();

  const { data: organization } = await supabase
    .from("organizations")
    .select("name")
    .eq("id", profile.organization_id)
    .single();

  return {
    user: { id: user.id, email: user.email ?? "" },
    profile,
    organizationName: organization?.name ?? "org",
    mfaCurrentLevel: (aal?.currentLevel as "aal1" | "aal2" | undefined) ?? "aal1",
    mfaNextLevel: (aal?.nextLevel as "aal1" | "aal2" | undefined) ?? "aal1",
  };
});

// Escrita (criar/editar alvo, projeto, scan, finding) exige role
// admin/pentester + MFA já verificado na sessão (aal2) — mesma regra da
// RLS (can_write()), checada aqui só para dar uma mensagem de erro
// amigável antes de tentar o INSERT/UPDATE.
export function canWrite(session: SessionInfo): boolean {
  return (
    (session.profile.role === "admin" || session.profile.role === "pentester") &&
    session.mfaCurrentLevel === "aal2"
  );
}
