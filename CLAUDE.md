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

Organização única (sem multi-tenant no MVP, mas manter RLS por boa prática). Perfis: Admin (gerencia usuários, aprova alvos, vê tudo), Pentester/Analista (cria projetos, roda scans, edita relatórios), Visualizador/Gestor (só leitura). MFA obrigatório para Admin e Pentester — imposto na própria RLS (ver abaixo), não só na UI.

## Supabase — projeto, schema e auth

- Projeto: `sentinela` (ref `fiejgbbpkxmkuwcfodpv`, região `sa-east-1`), na organização Supabase do usuário. Gerenciado via `supabase` CLI (`npx supabase`, projeto vinculado em `supabase/`).
- Schema completo em `supabase/migrations/` (aplicar sempre via nova migração, nunca editando uma já aplicada). Tabelas: `organizations`, `users` (perfil 1:1 com `auth.users`), `targets`, `projects`, `scans`, `findings`, `audit_log`. RLS habilitado em todas, usando as funções `current_org_id()`, `current_role()`, `mfa_satisfied()`, `can_write()`, `is_admin()` (security definer, evitam recursão de RLS).
- **Login é por usuário/senha, não e-mail** (decisão do usuário, diverge do prompt original que citava Supabase Auth "padrão"). Cada conta tem um `username` em `public.users` e um e-mail técnico sintético em `auth.users` (`<username>@users.sentinela.local`, nunca exibido nem usado para enviar nada). A função `public.email_for_username(username)` (security definer, `grant execute` para `anon`/`authenticated`) resolve usuário → e-mail técnico antes de chamar `signInWithPassword`. Ver `app/src/app/login/actions.ts`.
- **Gate de modalidade legal reforçado no banco**: `projects` tem um `CHECK` que exige `authorization_confirmed` + justificativa quando `legal_mode = 'ambiente_teste'`; `scans.is_active_tool = true` só passa pelo trigger `enforce_scan_legal_mode` se o projeto estiver autorizado em `ambiente_teste`. Não depende só do frontend.
- **Audit log automático**: criar/atualizar a modalidade legal de um projeto grava sozinho uma entrada em `audit_log` via trigger — não depende do código da aplicação lembrar de logar. `audit_log` não tem policy de UPDATE/DELETE e os privilégios foram revogados (`revoke update, delete ... from authenticated, anon`) — é apêndice-only de verdade.
- **MFA obrigatório**: `can_write()`/`is_admin()` exigem `auth.jwt()->>'aal' = 'aal2'` (segundo fator já verificado na sessão) além do role. Isso significa que Admin/Pentester **não conseguem** criar/editar `targets`/`projects`/`scans`/`findings` até fazer enrollment de MFA (TOTP) pela API do Supabase Auth — ainda não há tela para isso no app (entra numa fase futura). É comportamento esperado, não bug.
- Chaves do projeto em `app/.env.local` (gitignored): `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (chave `publishable`, segura para o cliente). A `service_role`/secret key **não foi obtida nem salva em nenhum lugar** — só será necessária quando o worker Python (Fase 7+) precisar de acesso privilegiado; buscar na hora, direto do dashboard do Supabase.
- Primeira conta Admin criada diretamente via SQL (inserção em `auth.users`/`auth.identities`, contornando a necessidade da service role key): usuário `keittony.ferreira`. A senha foi definida pelo usuário e não fica registrada em nenhum arquivo do repositório.

## Peculiaridade de rede local (ambiente corporativo deste usuário)

A rede onde este projeto é desenvolvido intercepta TLS com um certificado próprio (proxy corporativo) e também bloqueia a porta direta do Postgres (usada pelo `supabase db push`). Isso já mordeu três vezes:
1. Download do binário nativo do SWC do Next — resolvido instalando `@next/swc-win32-x64-msvc` via `npm install` direto (que já respeita `strict-ssl=false`).
2. Download do Chromium do Playwright — precisou de `NODE_TLS_REJECT_UNAUTHORIZED=0` só durante o `playwright install`.
3. Chamadas HTTPS feitas pelo processo Node do Next.js (server actions chamando a API do Supabase) — resolvido de forma correta (sem desabilitar verificação TLS) com a flag `--use-system-ca` do Node 24, que faz o Node confiar na store de certificados do Windows (onde a CA corporativa já está instalada), igual o `curl` já fazia. Os scripts `dev`/`build`/`start` em `app/package.json` usam `cross-env NODE_OPTIONS=--use-system-ca` por causa disso — não remover.
4. `supabase db push`/`supabase link` com conexão direta ao Postgres (porta do pooler) dão `ECONNRESET` nessa rede — a porta é bloqueada. Alternativa que funciona: aplicar migrações via API de gerenciamento do Supabase sobre HTTPS (`POST https://api.supabase.com/v1/projects/{ref}/database/query` com o access token, corpo `{"query": "<sql>"}`), que passa pela mesma porta 443 liberada. Depois de aplicar, inserir manualmente a versão em `supabase_migrations.schema_migrations` para manter o histórico do CLI consistente (senão o CLI tenta reaplicar do zero quando a porta do Postgres estiver acessível). `supabase gen types typescript --project-id <ref>` também funciona normalmente nessa rede (usa a mesma API HTTPS, não a porta do Postgres).

## Padrões de UI autenticada (a partir da Fase 3)

- Rotas autenticadas ficam em `app/src/app/(app)/` (route group — não aparece na URL). O layout desse grupo chama `requireUser()` (`app/src/lib/supabase/auth.ts`, memoizado por request com `cache()`) e redireciona para `/login` se não houver sessão; ele também renderiza o `AppHeader` compartilhado (usuário, role, aviso de MFA pendente, nav, sair). Toda página nova autenticada entra dentro desse grupo, não fora dele.
- `canWrite(session)` (mesmo arquivo) replica a regra da RLS (`role in (admin,pentester) and aal2`) só para dar uma mensagem de erro amigável na UI antes de tentar o INSERT — a garantia de verdade continua sendo a RLS/CHECK no banco, nunca confiar só nessa checagem client/server-side da UI.
- Erros de banco viram mensagem amigável via `friendlyDbError()` (`app/src/lib/supabase/errors.ts`) — adicionar novos casos ali conforme novas constraints/triggers forem criadas, em vez de deixar o erro cru do Postgres vazar pra UI.
- Tipos do schema ficam em `app/src/lib/supabase/database.types.ts`, gerados via `supabase gen types typescript` (regenerar depois de qualquer migração nova) e plugados nos clients (`createClient<Database>`).

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
