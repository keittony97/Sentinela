"use client";

import { useActionState } from "react";
import { startScan, type ScanFormState } from "./actions";

const initialState: ScanFormState = { error: null };

export function StartScanForm({ targetId, projectId }: { targetId: string; projectId: string }) {
  const [state, formAction, pending] = useActionState(startScan, initialState);

  return (
    <form action={formAction} className="flex flex-col gap-2">
      <input type="hidden" name="target_id" value={targetId} />
      <input type="hidden" name="project_id" value={projectId} />
      <p className="text-xs text-[var(--color-fg-muted)]">
        Ferramenta disponível: <span className="text-[var(--color-fg)]">headers_tls</span>{" "}
        (verificação passiva de headers de segurança e certificado TLS — sem ferramentas ativas
        ainda).
      </p>
      {state.error && (
        <p className="text-[var(--color-critical)]" role="alert">
          [ERRO] {state.error}
        </p>
      )}
      <button
        type="submit"
        disabled={pending}
        className="w-fit border border-[var(--color-border-bright)] bg-[var(--color-bg-inset)] px-3 py-1.5 text-sm text-[var(--color-phosphor)] hover:bg-[var(--color-phosphor)] hover:text-black disabled:opacity-50"
      >
        {pending ? "iniciando..." : "rodar verificação de headers/TLS »"}
      </button>
    </form>
  );
}
