"use client";

import { useActionState } from "react";
import { createTarget, type TargetFormState } from "../actions";

const initialState: TargetFormState = { error: null };

export function TargetForm() {
  const [state, formAction, pending] = useActionState(createTarget, initialState);

  return (
    <form action={formAction} className="flex flex-col gap-4 text-sm">
      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">nome do alvo:</span>
        <input
          name="name"
          type="text"
          required
          placeholder="ex: Portal RH"
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">URL:</span>
        <input
          name="url"
          type="text"
          required
          placeholder="https://portal-rh.empresa.com"
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      <fieldset className="flex flex-col gap-1">
        <legend className="text-[var(--color-fg-dim)]">escopo:</legend>
        <label className="flex items-center gap-2">
          <input type="radio" name="scope" value="internet" defaultChecked />
          <span>Internet (público)</span>
        </label>
        <label className="flex items-center gap-2">
          <input type="radio" name="scope" value="intranet" />
          <span>Intranet (rede interna/VPN)</span>
        </label>
      </fieldset>

      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">dono do ativo (opcional):</span>
        <input
          name="asset_owner"
          type="text"
          placeholder="ex: Time de RH"
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

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
        {pending ? "salvando..." : "cadastrar alvo »"}
      </button>
    </form>
  );
}
