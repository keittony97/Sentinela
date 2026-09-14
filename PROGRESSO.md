# Progresso — Sentinela

Atualize este arquivo ao final de cada sessão/fase de trabalho. O Claude Code deve ler este arquivo junto com o `CLAUDE.md` no início de cada sessão para saber onde o projeto parou.

## Status atual

**Fase em andamento:** Fase 1 — Esqueleto + identidade visual (concluída, pendente revisão do usuário)

## Checklist de fases

- [x] Fase 1 — Esqueleto + identidade visual
- [ ] Fase 2 — Modelo de dados + auth + RLS
- [ ] Fase 3 — Cadastro de alvo + gate de modalidade legal
- [ ] Fase 4 — Primeira ferramenta passiva, ponta a ponta
- [ ] Fase 5 — Demais ferramentas do modo "Verificação Externa"
- [ ] Fase 6 — Relatório exportável
- [ ] Fase 7 — Modo "Ambiente de Teste" (ferramentas ativas)
- [ ] Fase 8 — Migração para hospedagem local/intranet

## Decisões tomadas ao longo do caminho

- Projeto criado com Next.js 16 (não 14/15) — já é a versão estável disponível no momento. Convenções relevantes (params assíncronos, `next lint` removido, `middleware` → `proxy`) documentadas em `CLAUDE.md`.
- `CLAUDE.md` da raiz criado agora (estava referenciado no log da Sessão 0 mas nunca tinha sido escrito).
- Repositório git inicializado na raiz do projeto (`Sentinela/`), não dentro de `app/`.
- Ambiente de rede corporativo intercepta TLS com certificado próprio (`SELF_SIGNED_CERT_IN_CHAIN`) em downloads binários diretos (SWC do Next.js, browsers do Playwright) — `npm install` de pacotes funciona normalmente (`strict-ssl=false` já configurado), mas downloads diretos via fetch precisam de `NODE_TLS_REJECT_UNAUTHORIZED=0` pontual. Se isso voltar a acontecer em instalações futuras, é o mesmo problema.

## Pendências / bloqueios conhecidos

- Nenhum bloqueio ativo. Fase 1 aguardando validação visual do usuário antes de seguir para a Fase 2.

## Log de sessões

### Sessão 0 — Planejamento
Documento inicial (`CLAUDE.md`) definido antes de qualquer código.

### Sessão 1 — 2026-09-14 — Fase 1: Esqueleto + identidade visual
- Repositório git inicializado na raiz.
- App Next.js 16 (TypeScript + Tailwind v4 + App Router) criado em `app/`.
- Tema "hacker de filme" implementado: fundo preto, fonte JetBrains Mono, paleta verde fosforescente/âmbar/ciano, scanlines/CRT sutis, cursor piscando.
- Componentes reutilizáveis em `app/src/components/terminal/`: `TerminalWindow`, `TerminalPrompt`, `TypingText`, `SeverityBadge` (Crítico/Alto/Médio/Baixo/Informativo).
- Tela inicial (`app/src/app/page.tsx`) monta um mock do futuro dashboard (alvos, achados, log de scan em andamento) só para validar o visual — sem lógica de negócio real ainda.
- Build (`next build`) e lint (`eslint .`) passando sem erros.
- Validação visual feita via Playwright headless (screenshot + checagem de console sem erros) — renderização confirmada correta, sem erros de console.
- `CLAUDE.md` da raiz escrito documentando stack, gate de modalidade legal, RBAC, identidade visual e ordem de construção.

**Próximo passo:** Fase 2 — subir Supabase, definir tabelas (`organizations`, `users`, `targets`, `projects`, `scans`, `findings`, `audit_log`) e ativar RLS antes de escrever qualquer tela que leia dados reais.
