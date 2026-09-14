"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

type Step =
  | { kind: "idle" }
  | { kind: "enrolling"; factorId: string; qrCode: string; secret: string }
  | { kind: "done" };

export function MfaEnroll({ alreadyVerified }: { alreadyVerified: boolean }) {
  const [step, setStep] = useState<Step>(alreadyVerified ? { kind: "done" } : { kind: "idle" });
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const router = useRouter();

  function startEnroll() {
    setError(null);
    startTransition(async () => {
      const supabase = createClient();
      const { data, error: enrollError } = await supabase.auth.mfa.enroll({
        factorType: "totp",
        friendlyName: `authenticator-${Date.now()}`,
      });

      if (enrollError || !data) {
        setError(enrollError?.message ?? "Falha ao iniciar o enrollment de MFA.");
        return;
      }

      setStep({
        kind: "enrolling",
        factorId: data.id,
        qrCode: data.totp.qr_code,
        secret: data.totp.secret,
      });
    });
  }

  function verifyCode() {
    if (step.kind !== "enrolling") return;
    setError(null);
    startTransition(async () => {
      const supabase = createClient();
      const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
        factorId: step.factorId,
      });

      if (challengeError || !challenge) {
        setError(challengeError?.message ?? "Falha ao gerar o desafio de MFA.");
        return;
      }

      const { error: verifyError } = await supabase.auth.mfa.verify({
        factorId: step.factorId,
        challengeId: challenge.id,
        code,
      });

      if (verifyError) {
        setError("Código inválido. Confira o app autenticador e tente de novo.");
        return;
      }

      setStep({ kind: "done" });
      router.refresh();
    });
  }

  if (step.kind === "done") {
    return (
      <p className="text-sm text-[var(--color-phosphor)]">
        [OK] MFA habilitado. Sua sessão já está no nível aal2 — você pode criar alvos e
        projetos.
      </p>
    );
  }

  if (step.kind === "idle") {
    return (
      <div className="flex flex-col gap-3 text-sm">
        <p className="text-[var(--color-fg-dim)]">
          Nenhum fator de MFA configurado. Admin e Pentester precisam habilitar TOTP (Google
          Authenticator, 1Password, Authy, etc.) antes de conseguir criar ou editar alvos,
          projetos e scans.
        </p>
        {error && <p className="text-[var(--color-critical)]">[ERRO] {error}</p>}
        <button
          type="button"
          onClick={startEnroll}
          disabled={pending}
          className="w-fit border border-[var(--color-border-bright)] bg-[var(--color-bg-inset)] px-3 py-1.5 text-[var(--color-phosphor)] hover:bg-[var(--color-phosphor)] hover:text-black disabled:opacity-50"
        >
          {pending ? "gerando QR code..." : "habilitar MFA »"}
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 text-sm">
      <p className="text-[var(--color-fg-dim)]">
        Escaneie o QR code com seu app autenticador e digite o código de 6 dígitos abaixo.
      </p>
      {/* eslint-disable-next-line @next/next/no-img-element -- QR code é um data: URI dinâmico do Supabase, sem otimização de imagem aplicável */}
      <img
        src={step.qrCode}
        alt="QR code para configurar o autenticador TOTP"
        width={200}
        height={200}
        className="border border-[var(--color-border)] bg-white p-2"
      />
      <p className="break-all text-xs text-[var(--color-fg-muted)]">
        Não consegue escanear? Chave manual: {step.secret}
      </p>

      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">código de 6 dígitos:</span>
        <input
          value={code}
          onChange={(e) => setCode(e.target.value)}
          inputMode="numeric"
          maxLength={6}
          className="w-32 border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 tracking-widest text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      {error && <p className="text-[var(--color-critical)]">[ERRO] {error}</p>}

      <button
        type="button"
        onClick={verifyCode}
        disabled={pending || code.length !== 6}
        className="w-fit border border-[var(--color-border-bright)] bg-[var(--color-bg-inset)] px-3 py-1.5 text-[var(--color-phosphor)] hover:bg-[var(--color-phosphor)] hover:text-black disabled:opacity-50"
      >
        {pending ? "verificando..." : "verificar »"}
      </button>
    </div>
  );
}
