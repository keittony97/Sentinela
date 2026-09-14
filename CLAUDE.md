# Sentinela — Plataforma de Pentest & Bug Bounty Corporativa

Documento de referência do projeto. Leia junto com `PROGRESSO.md` no início de cada sessão para saber onde o projeto parou. A especificação completa original está em `prompt-sistema-pentest-bugbounty.md`.

## O que é

Plataforma interna multiusuário para a equipe testar alvos internos (intranet) e externos (internet), com ou sem login, sob duas modalidades legais estritas — ver seção "Gate de modalidade legal" abaixo, que é a peça central do sistema.

## Estrutura do repositório

- `app/` — aplicação Next.js (frontend + API routes).
- `worker/` — serviço Python (FastAPI) que processa a fila de scans. Ver seção própria abaixo.
- `docker-compose.yml` — sobe o worker em container (Docker não está instalado na máquina de dev atual; testado rodando `uvicorn` direto).
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
- Chaves do projeto em `app/.env.local` (gitignored): `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (chave `publishable`, segura para o cliente). A `service_role`/secret key foi obtida na Fase 4 (o worker Python precisa bypassar RLS pra processar scans de qualquer org) e vive só em `worker/.env` (gitignored) — nunca no app Next.js, nunca no browser, nunca commitada.
- Primeira conta Admin criada diretamente via SQL (inserção em `auth.users`/`auth.identities`, contornando a necessidade da service role key): usuário `keittony.ferreira`. A senha foi definida pelo usuário e não fica registrada em nenhum arquivo do repositório.

## Peculiaridade de rede local (ambiente corporativo deste usuário)

A rede onde este projeto é desenvolvido intercepta TLS com um certificado próprio (proxy corporativo) e também bloqueia a porta direta do Postgres (usada pelo `supabase db push`). Isso já mordeu três vezes:
1. Download do binário nativo do SWC do Next — resolvido instalando `@next/swc-win32-x64-msvc` via `npm install` direto (que já respeita `strict-ssl=false`).
2. Download do Chromium do Playwright — precisou de `NODE_TLS_REJECT_UNAUTHORIZED=0` só durante o `playwright install`.
3. Chamadas HTTPS feitas pelo processo Node do Next.js (server actions chamando a API do Supabase) — resolvido de forma correta (sem desabilitar verificação TLS) com a flag `--use-system-ca` do Node 24, que faz o Node confiar na store de certificados do Windows (onde a CA corporativa já está instalada), igual o `curl` já fazia. Os scripts `dev`/`build`/`start` em `app/package.json` usam `cross-env NODE_OPTIONS=--use-system-ca` por causa disso — não remover.
4. `supabase db push`/`supabase link` com conexão direta ao Postgres (porta do pooler) dão `ECONNRESET` nessa rede — a porta é bloqueada. Alternativa que funciona: aplicar migrações via API de gerenciamento do Supabase sobre HTTPS (`POST https://api.supabase.com/v1/projects/{ref}/database/query` com o access token, corpo `{"query": "<sql>"}`), que passa pela mesma porta 443 liberada. Depois de aplicar, inserir manualmente a versão em `supabase_migrations.schema_migrations` para manter o histórico do CLI consistente (senão o CLI tenta reaplicar do zero quando a porta do Postgres estiver acessível). `supabase gen types typescript --project-id <ref>` também funciona normalmente nessa rede (usa a mesma API HTTPS, não a porta do Postgres).

## Worker de scans (a partir da Fase 4)

- `worker/main.py`: app FastAPI (só `/health` por enquanto) que sobe um loop de polling em background (`asyncio`) — a cada `POLL_INTERVAL_SECONDS` (padrão 2s), busca em `scans` o mais antigo com `status='na_fila'` e reivindica atomicamente via `UPDATE ... WHERE status='na_fila'` (evita corrida se um dia rodar mais de uma instância). Sem Redis/Celery por decisão explícita do usuário — fila simples via polling na própria tabela `scans`, mais simples de operar no estágio atual.
- `worker/db.py`: cliente fino sobre a API REST do PostgREST (`httpx`, sem SDK pesado), autenticado com a `service_role` key — o worker processa scans de qualquer org, então precisa bypassar RLS. Chave vive só em `worker/.env` (gitignored), nunca no app Next.js/browser.
- Ferramentas passivas em `worker/checks/` (todas seguem o contrato `run(url) -> (logs, findings)`, registradas em `TOOL_RUNNERS` em `main.py`; a lista espelhada pro frontend fica em `app/src/lib/scanTools.ts` — manter as duas em sincronia):
  - `security_headers.py` (`headers_tls`) — GET normal + inspeção de headers de segurança (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, exposição do header Server) e do certificado TLS (dias até expirar).
  - `subdomains.py` (`subdomains`) — Certificate Transparency via crt.sh, 100% passivo (nunca toca o alvo). Sinaliza subdomínios com nome potencialmente sensível (dev/staging/homolog/admin/...).
  - `exposed_files.py` (`exposed_files`) — GET em caminhos bem conhecidos (`.env`, `.git/config`, backups, etc.), com uma sondagem de baseline num caminho aleatório primeiro pra não confundir "soft 404" (servidor que retorna HTTP 200 pra qualquer URL) com um arquivo de verdade.
  - `exposed_ports.py` (`exposed_ports`) — consulta passiva ao Shodan (nunca faz port scan direto). Requer `SHODAN_API_KEY` em `worker/.env`; sem ela, registra um achado informativo dizendo que foi pulada em vez de falhar o scan.
  - `storage_exposure.py` (`storage_exposure`) — testa nomes de bucket S3/GCS derivados do domínio do alvo. **Importante**: nomes de bucket são um namespace global, então um "achado" aqui não prova que o bucket pertence à organização — a severidade fica em `medio` (não `alto`) e o título/descrição deixam isso explícito, pedindo confirmação manual de propriedade antes de tratar como real.
- `worker/test_checks.py` — script de desenvolvimento pra testar qualquer módulo de `checks/` isoladamente contra uma URL, sem precisar passar pelo banco/fila/UI: `python test_checks.py https://exemplo.com`. Útil pra iterar rápido numa ferramenta nova antes de plugar no pipeline completo.
- **`worker/net.py`**: patch de confiança de TLS (`truststore.inject_into_ssl()`), mesmo problema de rede corporativa do app Next (`--use-system-ca`), só que do lado Python — `httpx`/`ssl` por padrão usam o bundle da `certifi`, que não confia na CA da rede local. Todo módulo que faz chamada HTTPS direta (`db.py` e cada `checks/*.py`) importa `net` explicitamente (`import net  # noqa: F401`) — é idempotente e o patch é global por processo, mas cada arquivo declara a própria dependência em vez de confiar que "algum outro import antes" já cuidou disso (isso mordeu ao testar `checks/` isoladamente via `test_checks.py`, que não passava por `db.py`).

### Tela de execução de scan em tempo real

- `/alvos/[id]/projetos/[projectId]` dispara o scan (`startScan`, insere em `scans` com `status` default `na_fila`) e redireciona para `/alvos/[id]/projetos/[projectId]/scans/[scanId]`. A partir da Fase 5, `StartScanForm` mostra um checkbox por ferramenta passiva (`PASSIVE_TOOLS` em `app/src/lib/scanTools.ts`, todas marcadas por padrão) em vez de rodar só `headers_tls`; `tools_used` do scan vira a lista selecionada. A action valida que cada valor recebido está em `PASSIVE_TOOL_IDS` antes de gravar.
- Essa tela (`ScanLiveView.tsx`, client component) escuta `scan_logs`/`scans`/`findings` via Supabase Realtime (Postgres Changes) **e também reconcilia via fetch direto** assim que a inscrição conecta, além de um poll de segurança a cada 2s enquanto o scan não terminar. Isso não é redundância por paranoia: na prática, o worker (poll a cada 2s) processa scans simples mais rápido do que o navegador consegue abrir o WebSocket da Realtime e se inscrever — eventos que acontecem antes da inscrição ficar ativa **não são entregues retroativamente**. Sem o fallback, a tela ficava presa em "na fila" indefinidamente mesmo com o scan já concluído no banco. Ao adicionar novas telas com Realtime, replicar esse padrão (inscrever + reconciliar + poll de segurança até o estado ser terminal), não confiar só no evento chegar a tempo.
- **`REPLICA IDENTITY FULL`** em `scans`, `scan_logs` e `findings` (migração `20260914161500`) — com a identidade padrão (só chave primária), um `UPDATE` que só muda `status`/`started_at`/`finished_at` não carrega `organization_id` no WAL, e a Realtime precisa dessa coluna pra avaliar a policy de RLS (`organization_id = current_org_id()`); sem ela no payload, o evento é descartado silenciosamente. Se uma tabela nova entrar na publicação `supabase_realtime` e for atualizada por colunas que não incluem as usadas nas policies de RLS, aplicar `REPLICA IDENTITY FULL` nela também.

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

## Identidade visual — logo e animação de boot do login (implementado)

O usuário forneceu um protótipo HTML autônomo (`sentinela-login-animacao.html`, na raiz — reapareceu depois de ele ter apagado por engano; se sumir nas próximas sessões, o que importa já está portado no código abaixo, não precisa dele para nada além de referência histórica) com a animação de boot da logo. Portado para React em `app/src/app/login/`:

- `LoginBoot.tsx` — client component que controla a sequência via `setTimeout` (mesmos tempos do protótipo: 0/600/1000/1600/1800/2800/3100ms), acumulando classes CSS (`draw-outline`, `flash-corners`, `draw-cross`, `pulse-dot`, `typing`, `show-tagline`, `done`) num wrapper `.sentinela-boot`. Clique ou tecla a qualquer momento pula direto pro estado final (`skip()`); `prefers-reduced-motion` pula automaticamente sem nem começar a animar. Recebe o formulário de login de verdade como `children` (não reimplementa os campos — o protótipo tinha e-mail/senha estáticos só de mockup).
- CSS da animação em `globals.css`, seção "Boot animation da logo" — contorno do quadrado desenhando via `stroke-dashoffset`, 4 cantos em L acendendo em sequência (~80ms entre cada), mira central se desenhando (scale+opacity), ponto vermelho pulsando, nome "sentinela" com efeito de digitação (`width` animado em `ch`, não é o `transform`/`opacity` puro que a spec original pedia — como é só a largura de um `<span>` inline, sem afetar layout de mais nada ao redor, o reflow é local e imperceptível; não valia a complexidade de fazer via `clip-path` só por causa disso) + cursor piscando em loop contínuo, tagline com fade, formulário revelando com fade+slide enquanto a logo encolhe e migra pro topo.
- **Desvio deliberado da paleta do protótipo**: o HTML original usava cores próprias (`#33ff66`, `#ff3b3b`, `#1f6b45`, `#04120a`) ligeiramente diferentes dos tokens já em uso no resto do app (`--color-phosphor: #39ff6a`, `--color-critical: #ff5c5c`, etc). Em vez de introduzir uma segunda paleta "de marca" quase-idêntica, a logo usa os tokens que já existem — evita ter dois verdes/vermelhos sutilmente diferentes brigando na mesma tela quando o usuário loga e cai num dashboard que já usa a paleta original.
- **Bug corrigido durante a implementação**: a largura final do nome (`9ch`) cortava o último "a" de "sentinela" — a métrica de `ch` do JetBrains Mono não fecha exato para 9 caracteres. Ajustado para `calc(9ch + 4px)`.
- A tela `/login` (`page.tsx`) não usa mais `TerminalWindow`/`TerminalPrompt` — só para esta tela, a logo animada substitui esses elementos como identidade visual de entrada; as demais telas continuam no padrão de janela de terminal.
- **Ainda pendente**: as variantes estáticas do logo em SVG (`app/public/brand/logo-principal.svg`, `logo-icone.svg`, `logo-horizontal.svg`) para favicon, header/topbar e materiais institucionais — só a versão animada da tela de login foi feita. O motivo "mira/alvo com cantos em viewfinder" já existe como JSX inline dentro de `LoginBoot.tsx`; extrair para SVGs estáticos reaproveitando essa mesma geometria quando for a vez do header/favicon.

## Estratégia de hospedagem

Online agora (Supabase Cloud + Vercel/VPS + VPS isolada para o worker) → migração futura para intranet 100% local via Docker Compose. Nunca hardcoded: toda config sensível via variável de ambiente.

## Ordem de construção (não pular fases)

Ver `PROGRESSO.md` para o checklist detalhado e o status atual. Ordem: esqueleto visual → modelo de dados/auth/RLS → gate de modalidade legal → uma ferramenta passiva ponta a ponta → demais ferramentas passivas → relatório exportável → modo Ambiente de Teste (ativo) → migração para hospedagem local.
