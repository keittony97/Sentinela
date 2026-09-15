"use client";

import { useActionState } from "react";
import { updateOrganization, type OrganizationFormState } from "./actions";

const initialState: OrganizationFormState = { error: null, success: false };

export function OrganizationForm({
  name,
  contactEmail,
  canEdit,
}: {
  name: string;
  contactEmail: string | null;
  canEdit: boolean;
}) {
  const [state, formAction, pending] = useActionState(updateOrganization, initialState);

  if (!canEdit) {
    return (
      <dl className="flex flex-col gap-4 text-sm">
        <div className="flex flex-col gap-1">
          <dt className="text-[var(--color-fg-dim)]">nome da organização:</dt>
          <dd className="text-[var(--color-fg)]">{name}</dd>
        </div>
        <div className="flex flex-col gap-1">
          <dt className="text-[var(--color-fg-dim)]">contato comercial:</dt>
          <dd className="text-[var(--color-fg)]">{contactEmail ?? "(não informado)"}</dd>
        </div>
        <p className="text-xs text-[var(--color-fg-muted)]">
          Só Admin com MFA habilitado pode editar estes dados.
        </p>
      </dl>
    );
  }

  return (
    <form action={formAction} className="flex flex-col gap-4 text-sm">
      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">nome da organização:</span>
        <input
          name="name"
          type="text"
          required
          defaultValue={name}
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      <label className="flex flex-col gap-1">
        <span className="text-[var(--color-fg-dim)]">contato comercial (e-mail, opcional):</span>
        <input
          name="contact_email"
          type="email"
          placeholder="ex: comercial@empresa.com"
          defaultValue={contactEmail ?? ""}
          className="border border-[var(--color-border)] bg-[var(--color-bg-inset)] px-2 py-1.5 text-[var(--color-fg)] outline-none focus:border-[var(--color-phosphor)]"
        />
      </label>

      {state.error && (
        <p className="text-[var(--color-critical)]" role="alert">
          [ERRO] {state.error}
        </p>
      )}
      {state.success && !state.error && (
        <p className="text-[var(--color-phosphor)]">dados salvos.</p>
      )}

      <button
        type="submit"
        disabled={pending}
        className="mt-2 w-fit border border-[var(--color-border-bright)] bg-[var(--color-bg-inset)] px-3 py-1.5 text-[var(--color-phosphor)] transition-colors hover:bg-[var(--color-phosphor)] hover:text-black disabled:opacity-50"
      >
        {pending ? "salvando..." : "salvar »"}
      </button>
    </form>
  );
}
