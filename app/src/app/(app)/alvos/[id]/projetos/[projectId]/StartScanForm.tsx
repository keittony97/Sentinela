"use client";

import { useActionState } from "react";
import { startScan, type ScanFormState } from "./actions";
import { PASSIVE_TOOLS } from "@/lib/scanTools";

const initialState: ScanFormState = { error: null };

export function StartScanForm({ targetId, projectId }: { targetId: string; projectId: string }) {
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
