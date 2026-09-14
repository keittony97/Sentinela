"use server";

import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";

export type LoginState = { error: string | null };

const GENERIC_ERROR = "Usuário ou senha inválidos.";

export async function signIn(_prevState: LoginState, formData: FormData): Promise<LoginState> {
  const username = String(formData.get("username") ?? "").trim();
  const password = String(formData.get("password") ?? "");

  if (!username || !password) {
    return { error: "Informe usuário e senha." };
  }

  const supabase = await createClient();

  // Login é por usuário/senha; internamente o Supabase Auth ainda exige um
  // e-mail, então resolvemos usuário -> e-mail técnico via RPC antes de
  // autenticar. A função é security definer (roda antes de existir sessão).
  const { data: email, error: lookupError } = await supabase.rpc("email_for_username", {
    p_username: username,
  });

  if (lookupError || !email) {
    return { error: GENERIC_ERROR };
  }

  const { error: authError } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (authError) {
    return { error: GENERIC_ERROR };
  }

  redirect("/");
}
