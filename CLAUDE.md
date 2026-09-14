# Sentinela — Plataforma de Pentest & Bug Bounty Corporativa

Documento de referência do projeto. Leia junto com `PROGRESSO.md` no início de cada sessão para saber onde o projeto parou. A especificação completa original está em `prompt-sistema-pentest-bugbounty.md`.

## O que é

Plataforma interna multiusuário para a equipe testar alvos internos (intranet) e externos (internet), com ou sem login, sob duas modalidades legais estritas — ver seção "Gate de modalidade legal" abaixo, que é a peça central do sistema.

## Estrutura do repositório

- `app/` — aplicação Next.js (frontend + API routes). É o único código-fonte por enquanto.
- `PROGRESSO.md` — status das fases, decisões, pendências. Atualizar ao final de cada sessão.
- `prompt-sistema-pentest-bugbounty.md` — especificação funcional original, não editar; é a fonte da verdade do escopo.

## Stack

- **Frontend/API**: Next.js 16 (App Router, Turbopack), TypeScript, Tailwind CSS v4.
- **Banco/Auth**: Supabase (Postgres + RLS + Auth), Supabase Cloud na fase inicial, compatível com self-hosted para migração futura.
- **Worker de scans**: serviço Python separado (FastAPI + fila), containers Docker isolados por execução das ferramentas (ZAP, Nuclei, Nikto, sqlmap, testssl.sh). Ainda não iniciado.
- **Tudo em Docker/Docker Compose desde o dia 1**, mesmo hospedado em nuvem, para a migração futura para intranet ser troca de servidor, não reescrita.

## Convenções do Next.js 16

Este projeto foi criado já na v16 (breaking changes relevantes em relação a versões anteriores). Antes de editar código em `app/`, consultar `app/node_modules/next/dist/docs/` (ou `app/AGENTS.md`, mantido automaticamente pelo `next dev`). Pontos que já se aplicam:
- `params`/`searchParams` são assíncronos (`await`) em páginas/layouts/rotas. Use os helpers `PageProps`/`LayoutProps`/`RouteContext` (gerados por `next typegen`).
- `next lint` foi removido — lint é via ESLint CLI direto (`npx eslint .`), flat config.
- Middleware foi renomeado para `proxy` (arquivo `proxy.ts`, export `proxy`).
- Turbopack é o padrão para `dev` e `build`.

## Gate de modalidade legal (não negociável)

Todo projeto de teste declara, antes de iniciar, de forma imutável em audit log:
1. Escopo do alvo: Intranet ou Internet.
2. Autenticação: sem login / com login (credenciais de teste dedicadas, nunca de usuário real de produção).
3. Modalidade legal:
   - **Verificação Externa (Legal)** — só ferramentas passivas/não intrusivas. Nenhuma ferramenta ativa disponível neste modo.
   - **Ambiente de Teste** — exige checkbox + justificativa/nº de autorização (vai para audit log). Só aqui ficam liberadas ferramentas ativas (SQLi/XSS, fuzzing, brute-force, etc).

Essa trava é a parte mais fácil de errar sem perceber — qualquer tela ou endpoint que dispare uma ferramenta ativa tem que checar a modalidade do projeto no backend, não só esconder o botão no frontend.

## RBAC

Organização única (sem multi-tenant no MVP, mas manter RLS por boa prática). Perfis: Admin (gerencia usuários, aprova alvos, vê tudo), Pentester/Analista (cria projetos, roda scans, edita relatórios), Visualizador/Gestor (só leitura). MFA obrigatório para Admin e Pentester.

## Identidade visual — "hacker de filme"

Já implementada no esqueleto (`app/src/app/globals.css`, `app/src/components/terminal/`):
- Fundo preto/quase-preto, fonte monoespaçada (JetBrains Mono) em toda a UI.
- Paleta: verde fosforescente (`--color-phosphor`) como cor principal, âmbar e ciano como acentos, severidades com cores próprias (crítico vermelho quebra o verde de propósito).
- Componentes reutilizáveis: `TerminalWindow` (janela estilo terminal com barra de título), `TerminalPrompt` (`user@host:path$`), `TypingText` (efeito de digitação), `SeverityBadge` (Crítico/Alto/Médio/Baixo/Informativo).
- Scanlines/CRT sutis via overlay global em `layout.tsx`, cuidado para não prejudicar contraste (WCAG AA).
- Ao criar novas telas, reusar esses componentes em vez de criar cards genéricos brancos/sombra.

## Estratégia de hospedagem

Online agora (Supabase Cloud + Vercel/VPS + VPS isolada para o worker) → migração futura para intranet 100% local via Docker Compose. Nunca hardcoded: toda config sensível via variável de ambiente.

## Ordem de construção (não pular fases)

Ver `PROGRESSO.md` para o checklist detalhado e o status atual. Ordem: esqueleto visual → modelo de dados/auth/RLS → gate de modalidade legal → uma ferramenta passiva ponta a ponta → demais ferramentas passivas → relatório exportável → modo Ambiente de Teste (ativo) → migração para hospedagem local.
