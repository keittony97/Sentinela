# Sentinela — Plataforma de Pentest & Bug Bounty Corporativa

Este arquivo é lido automaticamente pelo Claude Code no início de toda sessão neste repositório. Ele contém o contexto completo do projeto e todas as fases planejadas. Antes de iniciar qualquer trabalho, leia também o `PROGRESSO.md` na raiz do projeto para saber em qual fase estamos e o que já foi concluído.

## CONTEXTO E OBJETIVO

Construir o **Sentinela**, uma plataforma interna, **multiusuário, de organização única** (sem necessidade de multi-tenant), de pentest e bug bounty para uso da equipe/empresa. Deve permitir testar **links internos (intranet)** e **links externos (internet)**, alvos **com login** e **sem login**. Toda análise precisa declarar explicitamente sob qual modalidade legal está sendo executada, e gerar relatórios técnicos completos com classificação de severidade e orientação de correção.

## BRANDING

Nome do produto: **Sentinela**. Usar em todo header/sidebar como prompt de terminal, ex: `sentinela@<nome-da-org>:~$`. Logo tipográfico (monoespaçado) ou glifo simples de "vigia"/olho estilizado.

## PERFIS DE USUÁRIO (RBAC)

- **Admin**: gerencia usuários, aprova alvos/escopos, acessa todos os relatórios.
- **Pentester/Analista**: cria projetos de teste, executa scans, edita relatórios, sobe evidências manuais.
- **Visualizador/Gestor**: só visualiza relatórios e status, sem poder disparar scans.

Autenticação via Supabase Auth, MFA obrigatório para Admin e Pentester. Organização única — RLS aplicado por boa prática, mas sem a complexidade de isolar múltiplas organizações.

## MODOS DE TESTE (núcleo do sistema)

Todo projeto de teste declara, obrigatoriamente, antes de iniciar:

1. **Escopo do alvo**: Intranet (rede interna/VPN) ou Internet (público).
2. **Autenticação**: Sem login / Com login (credenciais de teste dedicadas, nunca de usuário real de produção).
3. **Modalidade legal**:
   - **"Verificação Externa (Legal)"** — testes passivos e de reconhecimento leve, não intrusivos: headers de segurança, exposição de configs/chaves em código público, TLS/certificados (testssl.sh), descoberta de portas abertas e banner grabbing via módulo próprio (Nmap), permissões públicas em bancos/storage expostos, subdomínios públicos. Nenhuma ferramenta ativa/intrusiva (fuzzing, brute-force, exploração) disponível neste modo.
   - **"Ambiente de Teste"** — exige confirmação explícita de propriedade/autorização do alvo (checkbox + justificativa/nº do termo, vai para o audit log). Libera ferramentas ativas: SQLi/XSS, fuzzing, brute-force controlado de login, scanners de configuração ativa.

Declaração registrada de forma imutável no `audit_log` (usuário, data/hora, relatório vinculado).

## SCAN GERAL (visão de portfólio)

Tela "Scan Geral" por sistema/site cadastrado, com as duas modalidades acima (agendado ou sob demanda). Dashboard por alvo com histórico de scans, tendência de vulnerabilidades e status de correção (aberto / em correção / corrigido / aceito o risco).

## MOTOR DE VULNERABILIDADES E SEVERIDADE

- Severidade: Crítico, Alto, Médio, Baixo, Informativo (CVSS 3.1 ou versão simplificada). Lista sempre com Crítico no topo.
- Detalhe expansível por vulnerabilidade: como foi encontrada (ferramenta, request/response, payload, evidência), impacto, como corrigir (recomendação específica), referências (CWE, OWASP Top 10).
- Relatório completo exportável (PDF, opcionalmente Word): sumário executivo + detalhamento técnico + plano de remediação priorizado.

### Cabeçalho de conformidade e rastreabilidade (obrigatório em todo relatório)

Todo relatório exportado deve abrir com um cabeçalho de conformidade, gerado automaticamente a partir do `audit_log` e dos dados do scan, contendo:

- **Responsável técnico**: nome, matrícula/usuário e perfil (Admin/Pentester) de quem executou o teste, e período (início/fim).
- **Ferramentas utilizadas**: lista automática das ferramentas efetivamente disparadas naquele scan.
- **Declaração de metodologia e limites**: texto padrão afirmando que o teste seguiu estritamente a modalidade declarada (Verificação Externa ou Ambiente de Teste) e que **nenhum procedimento intrusivo/exploratório foi realizado além do estritamente necessário para confirmar a existência de cada vulnerabilidade** — sem extração, cópia ou manipulação de dados além do mínimo necessário para evidenciar a falha.
- **Nota de conformidade com a LGPD** (exibida sempre que o finding envolver dado pessoal — CPF, nome, telefone, e-mail, dados sensíveis etc.): referenciar a **Lei nº 13.709/2018**, art. 6º (princípios de minimização e segurança) e art. 46 (medidas de segurança exigidas do controlador/operador); declarar que eventual dado pessoal visualizado durante o teste foi tratado apenas para fins de confirmação e documentação da falha, sem armazenamento além do necessário ao relatório; e, quando aplicável, recomendar que a organização responsável avalie a necessidade de comunicação à ANPD e aos titulares conforme art. 48, como recomendação técnica — não como afirmação jurídica categórica.
- Esse texto de conformidade é um **template configurável** (armazenado no banco, não hardcoded no frontend), para poder ser revisado pelo jurídico da organização antes de entrar em produção.

## LOGS DE EXECUÇÃO (separado do relatório de vulnerabilidades)

Tela própria por scan, independente do relatório de findings:
- Stream ao vivo (WebSocket/Supabase Realtime) do output bruto das ferramentas, linha a linha.
- Histórico completo salvo por scan, com timestamp, ferramenta de origem e nível (info/warning/erro).
- Filtro por ferramenta e nível. Download do log bruto (.txt/.log) separado do relatório.
- Componente de terminal (ex: xterm.js), reforçando a estética visual.

## ARQUITETURA

- **Frontend**: Next.js (App Router) + TypeScript + Tailwind.
- **Backend/API**: Next.js API routes ou serviço Node separado (regras de negócio: projetos, usuários, relatórios).
- **Banco**: Supabase (Postgres) com Row Level Security desde o início.
- **Worker de orquestração de scans** (separado do Next.js): Python (FastAPI + Celery/RQ, fila Redis), disparando OWASP ZAP, Nuclei, Nikto, sqlmap, testssl.sh em containers Docker isolados por execução; normaliza saída em formato único (severidade, evidência, CWE) antes de gravar no banco. Módulos próprios em Python para regras específicas não cobertas pelas ferramentas prontas.
- **Reconhecimento de portas/serviços (substitui Shodan/Censys)**: módulo próprio em Python que roda **Nmap** contra o alvo já cadastrado (descoberta de portas abertas, banner grabbing, versão de serviço) e **testssl.sh** para certificado/TLS, montando uma "ficha" equivalente ao que o Shodan devolveria — mas gerada na hora, sob demanda, contra um alvo já declarado no sistema, sem custo de API/créditos mensais e sem escanear IPs de terceiros não relacionados ao projeto.
- **Fila/Jobs assíncronos**: Redis + status em tempo real via Supabase Realtime/WebSocket.
- **Isolamento de rede**: worker de "Ambiente de Teste" roda isolado (VPC separada ou container sem acesso à rede de produção).

### Estratégia de hospedagem: online agora → local (intranet) no futuro

- Tudo em Docker/Docker Compose desde o dia 1, mesmo rodando em nuvem.
- Supabase Cloud agora, schema/RLS/functions compatíveis com Supabase self-hosted (Docker Compose oficial) para migração futura.
- Next.js sem features exclusivas de plataforma de deploy — roda via `next start` em container padrão.
- Worker de scan já nasce em container Docker isolado — peça mais simples de mover.
- Toda configuração via variáveis de ambiente (nunca hardcoded).
- Fase inicial: Supabase Cloud + Vercel/VPS simples (frontend) + VPS pequena dedicada só para o worker.
- Fase futura: servidor/VM na intranet, stack completa via Docker Compose (Supabase self-hosted + Next.js + worker), dump do banco restaurado, DNS interno.

## MODELO DE DADOS (ponto de partida)

- `organizations`, `users` (com role), `targets` (url, tipo intranet/internet, dono do ativo)
- `projects` (vincula target + modo legal/teste + status de autorização)
- `scans` (tipo, ferramenta(s), status, timestamps)
- `findings` (severidade, CWE, evidência, recomendação, status de remediação, vinculado ao scan)
- `audit_log` (declarações de modalidade, autorizações, quem rodou o quê)

## TELAS PRINCIPAIS (MVP)

1. Login/MFA
2. Dashboard geral (alvos, status, vulnerabilidades críticas em aberto)
3. Cadastro de novo alvo/projeto (com o gate de modalidade legal)
4. Execução de scan (ferramentas disponíveis conforme o modo) + log de execução em tempo real
5. Relatório de resultados (lista + detalhe expansível + export)
6. Histórico/tendência por alvo
7. Gestão de usuários e permissões (Admin)

## VISUAL/UX — Estética "Hacker de Filme"

- Tema escuro puro (preto/quase-preto), fonte monoespaçada (JetBrains Mono, Fira Code) em toda a interface.
- Paleta verde fosforescente sobre preto (+ âmbar/ciano de acento); crítico em vermelho vibrante quebrando o padrão de propósito.
- Cursor piscando, efeito de digitação em telas de carregamento/scan, bordas tipo ASCII/box-drawing, scanlines/glow sutil (CRT), sem prejudicar legibilidade.
- Cards em formato de janela de terminal (barra de título `user@target:~$`), não cards brancos com sombra.
- Gráficos mantêm a paleta (linhas verdes/âmbar em fundo preto).
- Manter contraste e acessibilidade WCAG AA apesar do estilo.

## IDENTIDADE VISUAL — LOGO

O Sentinela tem três versões de logo, todas na paleta verde fosforescente (#33ff66) sobre fundo escuro quase-preto (#04120a), com o motivo central de "mira/alvo" (representando escaneamento) e cantos em L estilo viewfinder de câmera/scanner. O ponto central da mira é vermelho (#ff3b3b) — mesma lógica de quebra de padrão usada nas severidades críticas do resto do sistema.

- **Logo principal** (quadrado com o nome "sentinela" abaixo + cursor de terminal piscando): usar na tela de login e em materiais institucionais/splash.
- **Ícone isolado** (só a mira, sem texto): usar como favicon, avatar, ícone de app/PWA, e em qualquer lugar onde o espaço for muito reduzido.
- **Versão horizontal** (ícone compacto + nome ao lado): usar no header/topbar e na sidebar do dashboard, onde o espaço é uma faixa estreita.

Os três arquivos SVG ficam versionados no repositório em `/public/brand/` (ex: `logo-principal.svg`, `logo-icone.svg`, `logo-horizontal.svg`).

## ANIMAÇÃO DA TELA DE LOGIN

Ao carregar a tela de login, o logo principal do Sentinela deve ser "montado" com uma animação que reforça a estética de terminal/boot de sistema, não um simples fade-in genérico. Sequência (aprox. 2.5–3s total, pode ser pulada com qualquer tecla/clique):

1. Tela preta. Aparece o contorno do quadrado do logo (stroke) se desenhando com efeito de "traço" (stroke-dashoffset animado), como se estivesse sendo desenhado por um plotter.
2. Os quatro cantos em L do viewfinder piscam/acendem em sequência rápida (canto a canto, ~80ms de intervalo entre eles), como se o sistema estivesse "calibrando" a mira.
3. O círculo e as linhas da mira central se desenham do centro para fora, terminando com o ponto vermelho central "acendendo" com um leve pulso (scale 0.5 → 1, opacity 0 → 1).
4. O nome "sentinela" aparece com efeito de digitação (typing effect), letra por letra, como se estivesse sendo digitado em um terminal, terminando com o cursor verde piscando ao lado (loop de piscar contínuo, mesmo depois da animação principal terminar).
5. Por último, a tagline "pentest & bug bounty" aparece com um fade rápido.
6. Após a sequência, o formulário de login (campos de e-mail/senha, MFA) aparece com um fade+slide sutil de baixo para cima, e o logo reduz suavemente de tamanho e migra para o topo da tela, como cabeçalho fixo.

Requisitos técnicos:
- Implementar com CSS animations/keyframes ou uma lib leve (ex: Framer Motion, se já estiver no projeto) — evitar dependência pesada só para essa animação.
- Deve respeitar `prefers-reduced-motion`: se o usuário tiver essa preferência ativada no sistema operacional, pular direto para o estado final (logo estático + formulário visível), sem nenhuma das animações de desenho/digitação.
- A animação roda uma vez por carregamento de página (não repete ao errar login, por exemplo) — só o cursor do "sentinela" continua piscando em loop.
- Performance: usar apenas `transform`, `opacity` e `stroke-dashoffset` para animar (evitar animar `width`/`height`/`top`/`left`, que forçam reflow).



Trabalhe uma fase por vez. Ao concluir uma fase, atualize o `PROGRESSO.md` antes de encerrar a sessão.

### Fase 1 — Esqueleto + identidade visual
Shell do Next.js com o tema "terminal hacker" completo: cores, fonte, componente de janela de terminal reutilizável, efeito de digitação. Sem lógica de negócio ainda.

### Fase 2 — Modelo de dados + auth + RLS
Subir Supabase, criar as tabelas do modelo de dados, ativar RLS, configurar Supabase Auth com MFA e os três perfis (Admin, Pentester, Visualizador).

### Fase 3 — Cadastro de alvo + gate de modalidade legal
Tela de cadastro de alvo/projeto com a declaração obrigatória de escopo, autenticação e modalidade legal (incluindo o campo de justificativa/autorização para "Ambiente de Teste"), gravando no `audit_log`.

### Fase 4 — Primeira ferramenta passiva, ponta a ponta
Uma única ferramenta simples (ex: verificação de headers de segurança/TLS) integrada do início ao fim: disparar → log de execução em tempo real → salvar finding → aparecer no relatório. Valida toda a arquitetura (fila, worker, realtime, banco) em escala pequena.

### Fase 5 — Demais ferramentas do modo "Verificação Externa"
Reaproveitar o pipeline validado na Fase 4 para as demais ferramentas passivas.

### Fase 6 — Relatório exportável
Geração de PDF (e opcionalmente Word) a partir dos findings reais já no banco.

### Fase 7 — Modo "Ambiente de Teste" (ferramentas ativas)
Integração de ZAP/Nuclei/sqlmap etc., isolamento de rede do worker, permissões mais finas por perfil.

### Fase 8 — Migração para hospedagem local/intranet
Quando o produto estiver validado: subir a stack completa via Docker Compose num servidor da intranet, Supabase self-hosted, restaurar dump, DNS interno.

---

## Notas operacionais e de implementação

Tudo abaixo é conhecimento acumulado durante a implementação (Fases 1–7), mantido aqui pra não se perder entre sessões — as seções acima são a especificação/planejamento; esta é a realidade de como foi construído. Ver `PROGRESSO.md` pro checklist de fases e o log sessão a sessão.

### Estrutura do repositório

- `app/` — aplicação Next.js 16 (App Router, Turbopack, TypeScript, Tailwind v4).
- `worker/` — serviço Python (FastAPI) que processa a fila de scans.
- `supabase/` — migrations do schema (aplicar sempre via nova migração, nunca editando uma já aplicada).
- `docker-compose.yml` — sobe o worker em container (Docker não está instalado na máquina de dev atual; testado rodando `uvicorn`/`python` direto).

### Convenções do Next.js 16

Projeto criado já na v16 (breaking changes em relação a versões anteriores). Antes de editar código em `app/`, consultar `app/node_modules/next/dist/docs/` ou `app/AGENTS.md`. Pontos que já se aplicam:
- `params`/`searchParams` são assíncronos (`await`) em páginas/layouts/rotas/route handlers.
- `next lint` foi removido — lint via ESLint CLI direto (`npx eslint .`), flat config.
- Middleware foi renomeado para `proxy` (arquivo `app/src/proxy.ts`, export `proxy`).
- Turbopack é o padrão para `dev` e `build`.

### Supabase — projeto, schema e auth

- Projeto: `sentinela` (ref `fiejgbbpkxmkuwcfodpv`, região `sa-east-1`). Gerenciado via `supabase` CLI (`npx supabase`, projeto vinculado em `supabase/`).
- Tabelas: `organizations`, `users` (perfil 1:1 com `auth.users`, tem `username`), `targets`, `projects`, `scans`, `findings`, `audit_log`, `scan_logs`. RLS habilitado em todas, usando funções security definer: `current_org_id()`, `current_role()`, `mfa_satisfied()`, `can_write()`, `is_admin()`.
- **Login é por usuário/senha, não e-mail** (decisão do usuário). Cada conta tem `username` em `public.users` e um e-mail técnico sintético em `auth.users` (`<username>@users.sentinela.local`). A função `public.email_for_username(username)` (security definer) resolve usuário → e-mail técnico antes de `signInWithPassword`. Ver `app/src/app/login/LoginForm.tsx` — é tudo client-side (não server action), porque também trata o desafio de MFA (challenge/verify) pra contas que já têm fator verificado, não só o enrollment inicial.
- **Gate de modalidade legal reforçado no banco**: `projects` tem `CHECK` exigindo `authorization_confirmed` + justificativa quando `legal_mode='ambiente_teste'`. Trigger `enforce_scan_legal_mode` em `scans` (before insert/update) bloqueia `is_active_tool=true` a menos que o projeto esteja `ambiente_teste` autorizado **e** o usuário que disparou (`triggered_by`) seja `admin` — e registra automaticamente no `audit_log` (`action='active_scan_triggered'`, só no INSERT, não a cada UPDATE de status).
- **Audit log automático**: criar/atualizar a modalidade legal de um projeto, ou disparar um scan ativo, grava sozinho no `audit_log` via trigger. Tabela é apêndice-only (sem policy de UPDATE/DELETE, privilégios revogados de `authenticated`/`anon`).
- **MFA obrigatório**: `can_write()`/`is_admin()` exigem `auth.jwt()->>'aal' = 'aal2'`. Ferramentas ativas exigem além disso `role='admin'`.
- Chaves em `app/.env.local` (gitignored): `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY` (publishable, segura pro cliente). A `service_role` key vive só em `worker/.env` (gitignored) — nunca no app Next.js/browser.
- Tipos TypeScript em `app/src/lib/supabase/database.types.ts`, gerados via `supabase gen types typescript --project-id <ref>` — regenerar depois de qualquer migração nova.
- **`REPLICA IDENTITY FULL`** em `scans`, `scan_logs` e `findings` — com a identidade padrão (só chave primária), um `UPDATE` que só muda `status`/`started_at`/`finished_at` não carrega `organization_id` no WAL, e a Realtime precisa dessa coluna pra avaliar a policy de RLS; sem ela no payload, o evento é descartado silenciosamente. Aplicar em qualquer tabela nova que entrar na publicação `supabase_realtime` e seja atualizada por colunas fora das usadas nas policies.

### Peculiaridade de rede local (ambiente corporativo deste usuário)

A rede onde este projeto é desenvolvido intercepta TLS com certificado próprio em alguns domínios (proxy corporativo) e bloqueia a porta direta do Postgres. Isso já mordeu várias vezes:
1. Downloads de binários nativos (SWC do Next, Chromium do Playwright) — resolvido com `npm install` direto do pacote, ou `NODE_TLS_REJECT_UNAUTHORIZED=0` pontual só durante o download.
2. Chamadas HTTPS do processo Node do Next (server actions → Supabase) — resolvido com `NODE_OPTIONS=--use-system-ca` (Node passa a confiar na store de certificados do Windows). Já embutido nos scripts `dev`/`build`/`start` de `app/package.json` via `cross-env` — não remover.
3. Mesmo problema do lado Python: `httpx`/`ssl` por padrão usam o bundle da `certifi`. Resolvido com `truststore.inject_into_ssl()`, centralizado em `worker/net.py` — todo módulo que faz HTTPS direto (`db.py`, cada `checks/*.py` que usa `httpx`) importa `net` explicitamente no topo (`import net  # noqa: F401`). Não depender de "algum outro import antes já ter feito isso" — isso já causou um bug real ao testar um `checks/*.py` isolado sem passar por `db.py`.
4. `supabase db push`/`supabase link` com conexão direta ao Postgres dão `ECONNRESET` — porta bloqueada. Alternativa: aplicar migrações via API de gerenciamento do Supabase sobre HTTPS (`POST https://api.supabase.com/v1/projects/{ref}/database/query`, corpo `{"query": "<sql>"}`), e inserir manualmente a versão em `supabase_migrations.schema_migrations` depois. `supabase gen types typescript` também usa essa mesma API HTTPS, funciona normal.

### Worker de scans

- `worker/main.py`: FastAPI (só `/health`) com loop de polling em background (`asyncio`) — a cada `POLL_INTERVAL_SECONDS` (padrão 2-3s), busca o scan mais antigo `status='na_fila'` e reivindica atomicamente via `UPDATE ... WHERE status='na_fila'`. Sem Redis/Celery — fila simples via polling na própria tabela `scans` (decisão explícita do usuário).
- `worker/db.py`: cliente fino sobre a API REST do PostgREST (`httpx`), autenticado com `service_role` key — bypassa RLS de propósito (processa scans de qualquer org).
- `worker/test_checks.py` / `worker/test_injection.py` (descartável, recriar se precisar): testar um módulo de `checks/` isolado contra uma URL, sem passar pelo banco/fila/UI.
- Ferramentas em `worker/checks/`, todas com o contrato `run(url) -> (logs, findings)`, registradas em `TOOL_RUNNERS` em `main.py`. Lista espelhada pro frontend em `app/src/lib/scanTools.ts` (`PASSIVE_TOOLS`/`ACTIVE_TOOLS`) — manter sincronizado.

**Passivas** (`is_active_tool=false`, disponíveis em qualquer modalidade legal):
- `security_headers.py` (`headers_tls`) — headers de segurança + validade do certificado TLS (via `ssl` do Python, sem depender de testssl.sh).
- `subdomains.py` (`subdomains`) — Certificate Transparency via crt.sh, nunca toca o alvo.
- `exposed_files.py` (`exposed_files`) — caminhos sensíveis bem conhecidos (`.env`, `.git/config`, backups...), com sondagem de baseline num caminho aleatório pra não confundir "soft 404" com arquivo de verdade. **Importante**: sempre descarta path/query/fragment da URL do alvo antes de concatenar os caminhos candidatos (`urlparse` → só `scheme://netloc`) — um alvo com `?a=1&b=2` na URL, concatenado ingenuamente, vira parte da query string em endpoints que ecoam a query (ex: `/get` de APIs de teste), gerando falso positivo em massa. Já mordeu uma vez.
- `port_scan.py` (`port_scan`) — **substitui a abordagem via Shodan/Censys** (existiu brevemente como `exposed_ports.py`, removido). Roda Nmap (`-sT`, TCP connect scan, não precisa de privilégio elevado nem driver de captura de pacotes) direto contra o alvo já cadastrado — sem custo de API/créditos, sem depender de dados de terceiros desatualizados, sem escanear IPs não relacionados ao projeto. Binário localizado via `shutil.which("nmap")` ou fallback pro caminho padrão do Windows; se não encontrado, registra achado informativo em vez de falhar. `worker/Dockerfile` instala `nmap` via apt pro deploy em container.
- `storage_exposure.py` (`storage_exposure`) — testa nomes de bucket S3/GCS derivados do domínio do alvo. Severidade fica em `medio` (não `alto`) com aviso explícito de "confirmar propriedade" — nomes de bucket são um namespace global, então bater o nome não prova que pertence à organização do alvo (confirmado na prática: achou um bucket real de terceiro sem relação nenhuma com o alvo testado).

**Ativas** (`is_active_tool=true`, só em projeto `ambiente_teste` autorizado + usuário `admin` — reforçado no banco via trigger, checado de novo no worker por defesa em profundidade, e escondido na UI se as condições não baterem):
- `basic_injection_probe.py` (`basic_injection_probe`) — sonda de XSS refletido (marcador com tags HTML, verifica se volta sem escape) e SQLi baseado em erro (aspas simples + padrões de mensagem de erro de banco conhecidos) nos parâmetros de query já existentes na URL do alvo. Não explora nada de verdade (sem UNION SELECT, sem blind/time-based, sem brute-force). Se a URL não tem parâmetros, registra achado informativo em vez de não fazer nada.

**Pendente/não implementado**: testssl.sh (a spec menciona pra TLS mais profundo — cipher suites, protocolos vulneráveis; hoje `security_headers.py` só checa expiração do certificado via `ssl` do Python, mais simples). ZAP/Nuclei/sqlmap de verdade (a spec original os menciona; dado o esforço de integração — Docker por execução, isolamento de rede — e que `basic_injection_probe.py` já cobre o caso de uso principal de SQLi/XSS de forma mais leve, ficou de fora por ora). Fuzzing e brute-force de login controlado também não implementados.

### Tela de execução de scan em tempo real

- `/alvos/[id]/projetos/[projectId]` dispara o scan (`startScan`, insere em `scans`) e redireciona para `/alvos/[id]/projetos/[projectId]/scans/[scanId]`. `StartScanForm` mostra checkbox por ferramenta passiva (todas marcadas por padrão) e, condicionalmente (`canRunActiveTools` calculado na page.tsx a partir de `session.profile.role` + `project.legal_mode` + `project.authorization_confirmed`), uma seção separada de ferramentas ativas (desmarcadas por padrão, destacada em vermelho).
- `ScanLiveView.tsx` (client component) escuta `scan_logs`/`scans`/`findings` via Supabase Realtime **e também reconcilia via fetch direto** assim que a inscrição conecta, mais um poll de segurança a cada 2s enquanto o scan não terminar. Necessário na prática: o worker processa scans simples mais rápido do que o navegador abre o WebSocket da Realtime e se inscreve — eventos antes da inscrição ficar ativa não são entregues retroativamente. Replicar esse padrão (inscrever + reconciliar + poll até estado terminal) em qualquer tela nova com Realtime.
- Scans com várias ferramentas selecionadas rodam **sequencialmente** no worker (não em paralelo) — um scan com 5-6 ferramentas pode levar 60-90s+. Isso é esperado, não bug; se a UX incomodar, paralelizar a execução das ferramentas dentro de um scan é uma melhoria futura possível.

### Relatório exportável (PDF) — Fase 6

- `@react-pdf/renderer` (não Puppeteer/Playwright) — gera PDF puro via componentes React próprios (`Document`/`Page`/`View`/`Text`), sem precisar de Chromium bundlado, mais leve pra deploy serverless/Vercel.
- `app/src/lib/pdf/ProjectReportDocument.tsx` — capa (dark, branding) + **cabeçalho de conformidade e rastreabilidade** (ver abaixo) + sumário executivo (contagem por severidade, lista de scans incluídos) + detalhamento técnico (um bloco por finding, ordenado por severidade) + plano de remediação priorizado. Usa fontes built-in do PDF (Helvetica/Courier) — sem registrar fonte customizada, evita depender de fetch de rede na hora de gerar o PDF.
- Route handler `app/src/app/(app)/alvos/[id]/projetos/[projectId]/relatorio/route.ts` — busca projeto/alvo/scans/findings (RLS já escopa por org), renderiza via `renderToBuffer`, devolve como `application/pdf` com `Content-Disposition: attachment`. O relatório é por **projeto**, agregando todos os scans desse projeto (não por scan individual).

**Cabeçalho de conformidade e rastreabilidade** (requisito do usuário, ver seção própria mais acima) — implementado como a segunda página do PDF, logo após a capa:
- Tabela `public.report_compliance_templates` (1 linha por organização, RLS: select pra todo mundo da org, update/insert só admin) guarda `methodology_statement` e `lgpd_note` — texto configurável pelo jurídico, **não hardcoded no frontend**. `{{modalidade}}` no texto de metodologia é substituído em tempo de geração pelo rótulo da modalidade legal do projeto. Se a organização não tiver linha (`maybeSingle()` retorna null), o componente cai pra um texto padrão embutido em `ProjectReportDocument.tsx` — nunca quebra a geração do relatório por falta de configuração.
- "Responsável técnico": busca `scans.triggered_by` + join manual com `public.users` (não embedding do PostgREST, mais explícito) pra listar usuário/role/período de cada scan incluído no relatório.
- "Ferramentas utilizadas": união de `tools_used` de todos os scans do projeto.
- Nota de conformidade LGPD é **condicional** — só aparece se algum finding do relatório "menciona" dado pessoal, decidido por uma heurística em `app/src/lib/pdf/personalDataDetection.ts` (regex de CPF/e-mail/telefone BR + palavras-chave como "cpf", "dado pessoal", "cartão de crédito", etc., varrendo título/descrição/impacto/evidência de cada finding). **É só uma heurística best-effort** — falso negativo é esperado (ex: nome de pessoa sozinho, sem CPF/e-mail junto, não é detectável por regex); o texto do próprio template já deixa isso como recomendação técnica, não afirmação jurídica categórica, exatamente por causa dessa limitação. Testado nos dois sentidos: finding sem menção a dado pessoal → nota ausente; finding com CPF/e-mail na evidência → nota aparece.

### Padrões de UI autenticada

- Rotas autenticadas em `app/src/app/(app)/` (route group). O layout chama `requireUser()` (`app/src/lib/supabase/auth.ts`, memoizado por request com `cache()` do React) e redireciona pra `/login` se não houver sessão; renderiza o `AppHeader` compartilhado (usuário, role, aviso de MFA pendente, nav, sair).
- `canWrite(session)` (mesmo arquivo) replica a regra da RLS só pra dar mensagem de erro amigável na UI antes do INSERT — a garantia de verdade é sempre a RLS/CHECK/trigger no banco.
- Erros de banco viram mensagem amigável via `friendlyDbError()` (`app/src/lib/supabase/errors.ts`).
- Identidade visual "hacker de filme" já implementada (`app/src/app/globals.css`, `app/src/components/terminal/`): fundo preto, JetBrains Mono, verde fosforescente (`--color-phosphor`) + âmbar/ciano de acento, `TerminalWindow`/`TerminalPrompt`/`TypingText`/`SeverityBadge`/`ScopeBadge`/`LegalModeBadge`/`ScanStatusBadge`. Reusar esses componentes em telas novas em vez de criar cards genéricos.
- **Animação de boot da tela de login** (`app/src/app/login/LoginBoot.tsx` + seção "Boot animation da logo" em `globals.css`): portada do protótipo HTML que o usuário forneceu (`sentinela-login-animacao.html`, na raiz — só referência histórica, o que importa já está no código). Sequência via classes CSS acumuladas + timers, pulável com clique/tecla, respeita `prefers-reduced-motion`. Usa os tokens de cor já existentes no app (não a paleta ligeiramente diferente do protótipo) pra não ter duas paletas quase-idênticas coexistindo. Ainda faltam as variantes estáticas do logo em SVG (favicon, header/topbar) — só a versão animada da tela de login foi feita.

### Ambiente de desenvolvimento local

- Servidores locais (`npm run dev` em `app/`, `uvicorn main:app` em `worker/`) não sobem sozinhos nem ficam supervisionados — rodar manualmente quando for testar/usar. Next.js 16 tem lockfile que impede duas instâncias simultâneas na mesma porta; se `npm run dev` disser "another server is already running", matar o processo pelo PID indicado antes de subir de novo.
- Docker não está instalado nesta máquina — `docker-compose.yml`/Dockerfiles existem e deveriam funcionar, mas só testados rodando os processos direto (sem container).
- Nmap 7.80 instalado via `winget install Insecure.Nmap` (não precisa de admin pra scan `-sT`).
