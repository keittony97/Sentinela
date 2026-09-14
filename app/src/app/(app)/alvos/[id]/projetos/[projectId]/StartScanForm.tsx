"use client";

import { useActionState } from "react";
import { startScan, type ScanFormState } from "./actions";
import { ACTIVE_TOOLS, PASSIVE_TOOLS } from "@/lib/scanTools";

const initialState: ScanFormState = { error: null };

export function StartScanForm({
  targetId,
  projectId,
  canRunActiveTools,
}: {
  targetId: string;
  projectId: string;
  canRunActiveTools: boolean;
}) {
  const [state, formAction, pending] = useActionState(startScan, initialState);

  return (
    <form action={formAction} className="flex flex-col gap-3">
      <input type="hidden" name="target_id" value={targetId} />
      <input type="hidden" name="project_id" value={projectId} />

      <fieldset className="flex flex-col gap-2">
        <legend className="text-xs text-[var(--color-fg-dim)]">
          ferramentas passivas (modo &quot;Verificação Externa&quot;):
        </legend>
        {PASSIVE_TOOLS.map((tool) => (
          <label key={tool.id} className="flex items-start gap-2 text-sm">
            <input type="checkbox" name="tools" value={tool.id} defaultChecked className="mt-1" />
            <span>
              <span className="text-[var(--color-fg)]">{tool.label}</span>
              <br />
              <span className="text-xs text-[var(--color-fg-muted)]">{tool.description}</span>
            </span>
          </label>
        ))}
      </fieldset>

      {canRunActiveTools ? (
        <fieldset className="flex flex-col gap-2 border border-[var(--color-critical)] p-3">
          <legend className="px-1 text-xs text-[var(--color-critical)]">
            ferramentas ativas (modo &quot;Ambiente de Teste&quot;):
          </legend>
          {ACTIVE_TOOLS.map((tool) => (
            <label key={tool.id} className="flex items-start gap-2 text-sm">
              <input type="checkbox" name="tools" value={tool.id} className="mt-1" />
              <span>
                <span className="text-[var(--color-critical)]">{tool.label}</span>
                <br />
                <span className="text-xs text-[var(--color-fg-muted)]">{tool.description}</span>
              </span>
            </label>
          ))}
        </fieldset>
      ) : (
        <p className="text-xs text-[var(--color-fg-muted)]">
          Ferramentas ativas indisponíveis aqui — exigem projeto em &quot;Ambiente de Teste&quot;
          autorizado e usuário Admin.
        </p>
      )}

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
        {pending ? "iniciando..." : "rodar verificação »"}
      </button>
    </form>
  );
}
