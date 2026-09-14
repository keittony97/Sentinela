import { TerminalPrompt } from "@/components/terminal/TerminalPrompt";
import { TerminalWindow } from "@/components/terminal/TerminalWindow";
import { TypingText } from "@/components/terminal/TypingText";
import { SeverityBadge } from "@/components/terminal/SeverityBadge";

const mockTargets = [
  { name: "portal-rh.empresa.com", scope: "internet", findings: 3 },
  { name: "erp.intranet.local", scope: "intranet", findings: 1 },
  { name: "api-pagamentos.empresa.com", scope: "internet", findings: 0 },
];

const mockFindings: { title: string; severity: Parameters<typeof SeverityBadge>[0]["severity"] }[] = [
  { title: "Cabeçalhos de segurança ausentes (HSTS, CSP)", severity: "medio" },
  { title: "Certificado TLS expirando em 12 dias", severity: "alto" },
  { title: "Bucket de storage com listagem pública", severity: "critico" },
  { title: "Subdomínio de staging exposto publicamente", severity: "baixo" },
  { title: "Versão de servidor divulgada no header Server", severity: "informativo" },
];

export default function Home() {
  return (
    <div className="flex flex-1 flex-col gap-6 px-4 py-6 sm:px-8 sm:py-10">
      <header className="flex flex-col gap-1 border-b border-[var(--color-border)] pb-4">
        <TerminalPrompt path="~/sentinela" className="text-lg sm:text-xl" />
        <h1 className="text-2xl font-bold text-[var(--color-phosphor)] glow-phosphor sm:text-3xl">
          <TypingText text="SENTINELA // Plataforma de Pentest &amp; Bug Bounty" speedMs={18} />
        </h1>
        <p className="text-sm text-[var(--color-fg-dim)]">
          Esqueleto de identidade visual — Fase 1. Dados abaixo são fictícios, apenas para validação de layout.
        </p>
      </header>

      <main className="grid flex-1 grid-cols-1 gap-6 lg:grid-cols-3">
        <TerminalWindow title="user@sentinela:~/alvos$" accent="phosphor" className="lg:col-span-1">
          <ul className="flex flex-col gap-3 text-sm">
            {mockTargets.map((target) => (
              <li key={target.name} className="flex flex-col gap-0.5">
                <span className="text-[var(--color-fg)]">{target.name}</span>
                <span className="flex items-center gap-2 text-xs text-[var(--color-fg-dim)]">
                  <span
                    className={
                      target.scope === "internet"
                        ? "text-[var(--color-cyan)]"
                        : "text-[var(--color-amber)]"
                    }
                  >
                    [{target.scope}]
                  </span>
                  {target.findings > 0
                    ? `${target.findings} achado(s) em aberto`
                    : "sem achados em aberto"}
                </span>
              </li>
            ))}
          </ul>
        </TerminalWindow>

        <TerminalWindow title="user@sentinela:~/achados$" accent="amber" className="lg:col-span-2">
          <ul className="flex flex-col gap-3 text-sm">
            {mockFindings.map((finding) => (
              <li
                key={finding.title}
                className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--color-border)] pb-2 last:border-none last:pb-0"
              >
                <span className="text-[var(--color-fg)]">{finding.title}</span>
                <SeverityBadge severity={finding.severity} />
              </li>
            ))}
          </ul>
        </TerminalWindow>

        <TerminalWindow title="user@sentinela:~/scan-em-andamento$" accent="cyan" className="lg:col-span-3">
          <div className="flex flex-col gap-1 text-sm text-[var(--color-fg-dim)]">
            <p>
              <span className="text-[var(--color-cyan)]">[INFO]</span> checando cabeçalhos de segurança de
              portal-rh.empresa.com...
            </p>
            <p>
              <span className="text-[var(--color-phosphor)]">[OK]</span> Strict-Transport-Security ausente
            </p>
            <p>
              <span className="text-[var(--color-amber)]">[WARN]</span> Content-Security-Policy não definido
            </p>
            <p className="flex items-center gap-1">
              <TerminalPrompt path="~/scan" />
              <span className="term-cursor" aria-hidden="true" />
            </p>
          </div>
        </TerminalWindow>
      </main>

      <footer className="border-t border-[var(--color-border)] pt-4 text-xs text-[var(--color-fg-muted)]">
        Modalidade legal ativa por projeto: Verificação Externa (Legal) ou Ambiente de Teste (autorizado). Nenhum
        scan real foi executado nesta tela.
      </footer>
    </div>
  );
}
