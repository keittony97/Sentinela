import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { LoginForm } from "./LoginForm";

export default function LoginPage() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 px-4 py-10">
      <TerminalPrompt path="~/login" className="text-lg" />
      <TerminalWindow title="user@sentinela:~/login$" accent="phosphor" className="w-full max-w-sm">
        <LoginForm />
      </TerminalWindow>
      <p className="max-w-sm text-center text-xs text-[var(--color-fg-muted)]">
        Acesso restrito à equipe autorizada. Admin e Pentester precisam de MFA
        habilitado para criar ou editar alvos, projetos e scans.
      </p>
    </div>
  );
}
