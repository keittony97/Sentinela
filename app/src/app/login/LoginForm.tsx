"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

const GENERIC_ERROR = "Usuário ou senha inválidos.";

export function LoginForm() {
  const [step, setStep] = useState<"credentials" | "mfa">("credentials");
  const [factorId, setFactorId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const router = useRouter();

  async function handleCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setPending(true);

    const formData = new FormData(event.currentTarget);
    const username = String(formData.get("username") ?? "").trim();
    const password = String(formData.get("password") ?? "");

    if (!username || !password) {
      setError("Informe usuário e senha.");
      setPending(false);
      return;
    }

    const supabase = createClient();

    // Login é por usuário/senha; o Supabase Auth ainda exige e-mail por
    // baixo dos panos, então resolvemos usuário -> e-mail técnico via RPC
    // antes de autenticar.
    const { data: email, error: lookupError } = await supabase.rpc("email_for_username", {
      p_username: username,
    });

    if (lookupError || !email) {
      setError(GENERIC_ERROR);
      setPending(false);
      return;
    }

    const { error: authError } = await supabase.auth.signInWithPassword({ email, password });
    if (authError) {
      setError(GENERIC_ERROR);
      setPending(false);
      return;
    }

    // Se a conta já tem MFA habilitado, o login com senha só entrega aal1
    // — falta o desafio do segundo fator antes de liberar a sessão (aal2).
    const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
    if (aal?.currentLevel === "aal1" && aal.nextLevel === "aal2") {
      const { data: factors } = await supabase.auth.mfa.listFactors();
      const totpFactor = factors?.totp?.[0];
      if (!totpFactor) {
        setError("MFA pendente mas nenhum fator encontrado. Contate um administrador.");
        setPending(false);
        return;
      }
      setFactorId(totpFactor.id);
      setStep("mfa");
      setPending(false);
      return;
    }

    router.push("/");
    router.refresh();
  }

  async function handleMfaCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!factorId) return;
    setError(null);
    setPending(true);

    const supabase = createClient();
    const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
      factorId,
    });
    if (challengeError || !challenge) {
      setError("Falha ao gerar o desafio de MFA.");
      setPending(false);
      return;
    }

    const { error: verifyError } = await supabase.auth.mfa.verify({
      factorId,
      challengeId: challenge.id,
      code,
    });
    if (verifyError) {
      setError("Código inválido. Confira o app autenticador e tente de novo.");
      setPending(false);
      return;
    }

    router.push("/");
    router.refresh();
  }

  if (step === "mfa") {
    return (
      <form onSubmit={handleMfaCode} className="flex flex-col gap-4 text-sm">
        <p className="text-[var(--color-fg-dim)]">
          Digite o código de 6 dígitos do seu app autenticador:
        </p>
        <input
          value={code}
          onChange={(e) => setCode(e.target.value)}
          inputMode="numeric"
          maxLength={6}
          autoFocus
          className="w-32 border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 tracking-widest text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
        {error && (
          <p className="text-[var(--color-critical)]" role="alert">
            [ERRO] {error}
          </p>
        )}
        <button
          type="submit"
          disabled={pending || code.length !== 6}
          className="mt-2 w-fit border border-[var(--color-border-bright)] bg-[var(--color-bg-inset)] px-3 py-1.5 text-[var(--color-phosphor)] transition-colors hover:bg-[var(--color-phosphor)] hover:text-black disabled:opacity-50"
        >
          {pending ? "verificando..." : "confirmar »"}
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={handleCredentials} className="flex flex-col gap-4 text-sm">
      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">usuário:</span>
        <input
          name="username"
          type="text"
          required
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">senha:</span>
        <input
          name="password"
          type="password"
          required
          autoComplete="current-password"
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      {error && (
        <p className="text-[var(--color-critical)]" role="alert">
          [ERRO] {error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="mt-2 border border-[var(--color-border-bright)] bg-[var(--color-bg-inset)] px-3 py-1.5 text-[var(--color-phosphor)] transition-colors hover:bg-[var(--color-phosphor)] hover:text-black disabled:opacity-50"
      >
        {pending ? "autenticando..." : "entrar »"}
      </button>
    </form>
  );
}
