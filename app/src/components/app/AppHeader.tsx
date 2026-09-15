import Link from "next/link";
import { signOut } from "@/app/(app)/actions";
import type { SessionInfo } from "@/lib/supabase/auth";

const roleLabel: Record<string, string> = {
  admin: "admin",
  pentester: "pentester",
  visualizador: "visualizador",
};

export function AppHeader({ session }: { session: SessionInfo }) {
  const mfaOk = session.mfaCurrentLevel === "aal2";

  return (
    <header className="flex flex-col gap-3 border-b border-[var(--color-border)] px-4 py-4 sm:px-8">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3 text-sm">
          <Link href="/" className="flex items-center" aria-label="Sentinela — dashboard">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src="/brand/logo-horizontal.svg" alt="Sentinela" className="h-7 w-auto" />
          </Link>
          <span className="h-5 w-px bg-[var(--color-border)]" aria-hidden="true" />
          <span className="whitespace-pre">
            <span className="text-[var(--color-phosphor)]">{session.profile.username}</span>
            <span className="text-[var(--color-fg-muted)]">@</span>
            <span className="text-[var(--color-cyan)]">{session.organizationName}</span>
            <span className="text-[var(--color-fg-muted)]">:~$</span>
          </span>
          <span className="rounded-sm border border-[var(--color-border-bright)] px-1.5 py-0.5 text-xs text-[var(--color-fg-dim)]">
            {roleLabel[session.profile.role] ?? session.profile.role}
          </span>
          {!mfaOk && (
            <Link
              href="/mfa"
              className="rounded-sm border border-[var(--color-amber)] px-1.5 py-0.5 text-xs text-[var(--color-amber)] hover:bg-[var(--color-amber)] hover:text-black"
            >
              MFA pendente
            </Link>
          )}
        </div>

        <form action={signOut}>
          <button
            type="submit"
            className="text-xs text-[var(--color-fg-dim)] underline decoration-dotted hover:text-[var(--color-critical)]"
          >
            sair
          </button>
        </form>
      </div>

      <nav className="flex flex-wrap gap-4 text-sm">
        <Link href="/" className="text-[var(--color-fg)] hover:text-[var(--color-phosphor)]">
          dashboard
        </Link>
        <Link href="/alvos" className="text-[var(--color-fg)] hover:text-[var(--color-phosphor)]">
          alvos
        </Link>
        <Link href="/organizacao" className="text-[var(--color-fg)] hover:text-[var(--color-phosphor)]">
          organização
        </Link>
        <Link href="/mfa" className="text-[var(--color-fg)] hover:text-[var(--color-phosphor)]">
          mfa
        </Link>
      </nav>
    </header>
  );
}
