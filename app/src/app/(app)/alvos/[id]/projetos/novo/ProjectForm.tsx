"use client";

import { useActionState, useState } from "react";
import { createProject, type ProjectFormState } from "../actions";

const initialState: ProjectFormState = { error: null };

export function ProjectForm({ targetId }: { targetId: string }) {
  const [state, formAction, pending] = useActionState(createProject, initialState);
  const [legalMode, setLegalMode] = useState<"verificacao_externa" | "ambiente_teste">(
    "verificacao_externa",
  );

  return (
    <form action={formAction} className="flex flex-col gap-4 text-sm">
      <input type="hidden" name="target_id" value={targetId} />

      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">nome do projeto:</span>
        <input
          name="name"
          type="text"
          required
          placeholder="ex: Verificação trimestral Q1"
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      <fieldset className="flex flex-col gap-1">
        <legend className="text-[var(--color-fg-dim)]">autenticação:</legend>
        <label className="flex items-center gap-2">
          <input type="radio" name="auth_mode" value="sem_login" defaultChecked />
          <span>Sem login</span>
        </label>
        <label className="flex items-center gap-2">
          <input type="radio" name="auth_mode" value="com_login" />
          <span>Com login (credenciais de teste dedicadas)</span>
        </label>
      </fieldset>

      <fieldset className="flex flex-col gap-2 border border-[var(--color-border)] p-3">
        <legend className="px-1 text-[var(--color-fg-dim)]">modalidade legal:</legend>

        <label className="flex items-start gap-2">
          <input
            type="radio"
            name="legal_mode"
            value="verificacao_externa"
            checked={legalMode === "verificacao_externa"}
            onChange={() => setLegalMode("verificacao_externa")}
            className="mt-1"
          />
          <span>
            <span className="text-[var(--color-phosphor)]">Verificação Externa (Legal)</span>
            <br />
            <span className="text-xs text-[var(--color-fg-muted)]">
              Testes passivos e não intrusivos. Nenhuma ferramenta ativa fica disponível neste
              modo.
            </span>
          </span>
        </label>

        <label className="flex items-start gap-2">
          <input
            type="radio"
            name="legal_mode"
            value="ambiente_teste"
            checked={legalMode === "ambiente_teste"}
            onChange={() => setLegalMode("ambiente_teste")}
            className="mt-1"
          />
          <span>
            <span className="text-[var(--color-critical)]">Ambiente de Teste</span>
            <br />
            <span className="text-xs text-[var(--color-fg-muted)]">
              Libera ferramentas ativas (SQLi, XSS, fuzzing, brute-force...). Exige confirmação
              de autorização abaixo.
            </span>
          </span>
        </label>

        {legalMode === "ambiente_teste" && (
          <div className="mt-2 flex flex-col gap-3 border-t border-[var(--color-border)] pt-3">
            <label className="flex items-center gap-2">
              <input type="checkbox" name="authorization_confirmed" required />
              <span>
                Confirmo que este alvo é de propriedade da empresa ou está formalmente
                autorizado para este teste.
              </span>
            </label>

            <label className="flex flex-col gap-1">
              <span className="text-[var(--color-fg-dim)]">nº do termo de autorização (opcional):</span>
              <input
                name="authorization_reference"
                type="text"
                className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
              />
            </label>

            <label className="flex flex-col gap-1">
              <span className="text-[var(--color-fg-dim)]">justificativa:</span>
              <textarea
                name="authorization_justification"
                required
                rows={3}
                placeholder="ex: alvo de propriedade da empresa, aprovado pelo time de segurança em..."
                className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
              />
            </label>

            <p className="text-xs text-[var(--color-fg-muted)]">
              Esta declaração fica registrada de forma imutável no log de auditoria, vinculada a
              você e à data/hora atual.
            </p>
          </div>
        )}
      </fieldset>

      {state.error && (
        <p className="text-[var(--color-critical)]" role="alert">
          [ERRO] {state.error}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="mt-2 w-fit border border-[var(--color-border-bright)] bg-[var(--color-bg-inset)] px-3 py-1.5 text-[var(--color-phosphor)] transition-colors hover:bg-[var(--color-phosphor)] hover:text-black disabled:opacity-50"
      >
        {pending ? "salvando..." : "criar projeto »"}
      </button>
    </form>
  );
}
