-- Sentinela — schema inicial (organizations, users, targets, projects, scans, findings, audit_log)
-- Organização única no MVP, mas modelo já preparado para multi-tenant futuro.

create extension if not exists pgcrypto;

-- ==========================================================================
-- ENUMS
-- ==========================================================================

create type public.user_role as enum ('admin', 'pentester', 'visualizador');
create type public.target_scope as enum ('intranet', 'internet');
create type public.auth_mode as enum ('sem_login', 'com_login');
create type public.legal_mode as enum ('verificacao_externa', 'ambiente_teste');
create type public.project_status as enum ('rascunho', 'ativo', 'concluido', 'arquivado');
create type public.scan_status as enum ('na_fila', 'em_execucao', 'concluido', 'falhou', 'cancelado');
create type public.severity_level as enum ('critico', 'alto', 'medio', 'baixo', 'informativo');
create type public.remediation_status as enum ('aberto', 'em_correcao', 'corrigido', 'risco_aceito');

-- ==========================================================================
-- TABLES
-- ==========================================================================

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

-- Perfil de cada usuário autenticado (auth.users), 1:1 via id.
create table public.users (
  id uuid primary key references auth.users (id) on delete cascade,
  organization_id uuid not null references public.organizations (id) on delete restrict,
  email text not null,
  full_name text,
  role public.user_role not null default 'visualizador',
  created_at timestamptz not null default now()
);

create table public.targets (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete restrict,
  name text not null,
  url text not null,
  scope public.target_scope not null,
  asset_owner text,
  created_by uuid not null references public.users (id) on delete restrict,
  created_at timestamptz not null default now()
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete restrict,
  target_id uuid not null references public.targets (id) on delete restrict,
  name text not null,
  auth_mode public.auth_mode not null,
  legal_mode public.legal_mode not null,
  -- Gate de modalidade legal: "Ambiente de Teste" exige confirmação explícita
  -- de autorização, com justificativa/nº do termo. Isso alimenta o audit_log
  -- automaticamente (ver trigger log_project_legal_declaration abaixo).
  authorization_confirmed boolean not null default false,
  authorization_reference text,
  authorization_justification text,
  status public.project_status not null default 'rascunho',
  created_by uuid not null references public.users (id) on delete restrict,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint chk_ambiente_teste_autorizado check (
    legal_mode <> 'ambiente_teste'
    or (
      authorization_confirmed = true
      and authorization_justification is not null
      and length(trim(authorization_justification)) > 0
    )
  )
);

create table public.scans (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete restrict,
  project_id uuid not null references public.projects (id) on delete restrict,
  -- true para ferramentas ativas/intrusivas (SQLi, XSS, fuzzing, brute-force...).
  -- Só pode ser true se o projeto estiver em "ambiente_teste" e autorizado —
  -- verificado por trigger, não só por RLS (ver enforce_scan_legal_mode).
  is_active_tool boolean not null default false,
  tools_used text[] not null default '{}',
  status public.scan_status not null default 'na_fila',
  triggered_by uuid not null references public.users (id) on delete restrict,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.findings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete restrict,
  scan_id uuid not null references public.scans (id) on delete cascade,
  severity public.severity_level not null,
  title text not null,
  cwe text,
  owasp_category text,
  description text,
  impact text,
  recommendation text,
  reference_links text[] not null default '{}',
  evidence jsonb not null default '{}',
  remediation_status public.remediation_status not null default 'aberto',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Log de auditoria imutável: declarações de modalidade, autorizações, quem
-- rodou o quê. Sem policy de UPDATE/DELETE (ver seção RLS) + privilégios
-- revogados = ninguém, nem admin, edita ou apaga uma entrada já gravada.
create table public.audit_log (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete restrict,
  user_id uuid references public.users (id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id uuid,
  metadata jsonb not null default '{}',
  created_at timestamptz not null default now()
);

create index idx_users_organization on public.users (organization_id);
create index idx_targets_organization on public.targets (organization_id);
create index idx_projects_organization on public.projects (organization_id);
create index idx_projects_target on public.projects (target_id);
create index idx_scans_organization on public.scans (organization_id);
create index idx_scans_project on public.scans (project_id);
create index idx_findings_organization on public.findings (organization_id);
create index idx_findings_scan on public.findings (scan_id);
create index idx_audit_log_organization on public.audit_log (organization_id);
create index idx_audit_log_user on public.audit_log (user_id);

-- ==========================================================================
-- HELPER FUNCTIONS (security definer para evitar recursão de RLS)
-- ==========================================================================

create or replace function public.current_org_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select organization_id from public.users where id = auth.uid();
$$;

create or replace function public.current_role()
returns public.user_role
language sql
stable
security definer
set search_path = public
as $$
  select role from public.users where id = auth.uid();
$$;

-- MFA obrigatório para Admin/Pentester: true somente quando a sessão atual
-- já completou o segundo fator (aal2). Usado nas policies de escrita.
create or replace function public.mfa_satisfied()
returns boolean
language sql
stable
as $$
  select coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2';
$$;

create or replace function public.can_write()
returns boolean
language sql
stable
as $$
  select public.current_role() in ('admin', 'pentester') and public.mfa_satisfied();
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
as $$
  select public.current_role() = 'admin' and public.mfa_satisfied();
$$;

-- ==========================================================================
-- TRIGGERS — bootstrap de usuário, updated_at, gate legal, audit log
-- ==========================================================================

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger trg_projects_updated_at
before update on public.projects
for each row execute function public.set_updated_at();

create trigger trg_scans_updated_at
before update on public.scans
for each row execute function public.set_updated_at();

create trigger trg_findings_updated_at
before update on public.findings
for each row execute function public.set_updated_at();

-- Cria automaticamente o perfil em public.users quando alguém se cadastra
-- via Supabase Auth. Todo novo usuário entra como "visualizador" (menor
-- privilégio) na única organização existente; promoção a pentester/admin é
-- manual, feita por um admin.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_org_id uuid;
begin
  select id into v_org_id from public.organizations order by created_at asc limit 1;

  insert into public.users (id, organization_id, email, full_name, role)
  values (
    new.id,
    v_org_id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'full_name', new.email),
    'visualizador'
  );
  return new;
end;
$$;

create trigger trg_handle_new_user
after insert on auth.users
for each row execute function public.handle_new_user();

-- Gate de modalidade legal, camada de banco: nenhuma ferramenta ativa roda
-- fora de um projeto "ambiente_teste" com autorização confirmada — mesmo que
-- um endpoint da aplicação esqueça de checar isso antes de inserir o scan.
create or replace function public.enforce_scan_legal_mode()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_legal_mode public.legal_mode;
  v_authorized boolean;
begin
  select legal_mode, authorization_confirmed
    into v_legal_mode, v_authorized
    from public.projects
    where id = new.project_id;

  if new.is_active_tool and (v_legal_mode is distinct from 'ambiente_teste' or v_authorized is not true) then
    raise exception 'Ferramentas ativas só podem ser executadas em projetos na modalidade "Ambiente de Teste" com autorização confirmada.';
  end if;

  return new;
end;
$$;

create trigger trg_enforce_scan_legal_mode
before insert or update on public.scans
for each row execute function public.enforce_scan_legal_mode();

-- Toda declaração de modalidade legal (criação do projeto ou mudança dela)
-- é gravada automaticamente no audit_log — não depende do código da
-- aplicação lembrar de logar.
create or replace function public.log_project_legal_declaration()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.audit_log (organization_id, user_id, action, entity_type, entity_id, metadata)
  values (
    new.organization_id,
    auth.uid(),
    case when tg_op = 'INSERT' then 'project_created' else 'project_legal_mode_updated' end,
    'project',
    new.id,
    jsonb_build_object(
      'legal_mode', new.legal_mode,
      'auth_mode', new.auth_mode,
      'scope_target_id', new.target_id,
      'authorization_confirmed', new.authorization_confirmed,
      'authorization_reference', new.authorization_reference,
      'authorization_justification', new.authorization_justification
    )
  );
  return new;
end;
$$;

create trigger trg_log_project_insert
after insert on public.projects
for each row execute function public.log_project_legal_declaration();

create trigger trg_log_project_legal_update
after update of legal_mode, authorization_confirmed, authorization_reference, authorization_justification
on public.projects
for each row execute function public.log_project_legal_declaration();

-- ==========================================================================
-- ROW LEVEL SECURITY
-- ==========================================================================

alter table public.organizations enable row level security;
alter table public.users enable row level security;
alter table public.targets enable row level security;
alter table public.projects enable row level security;
alter table public.scans enable row level security;
alter table public.findings enable row level security;
alter table public.audit_log enable row level security;

-- organizations: todo mundo vê a própria organização; só admin (com MFA) edita.
create policy org_select on public.organizations
  for select using (id = public.current_org_id());

create policy org_update_admin on public.organizations
  for update using (id = public.current_org_id() and public.is_admin());

-- users: qualquer membro da org vê os colegas; cada um edita seu próprio
-- perfil (exceto role); só admin com MFA edita role/qualquer perfil da org.
create policy users_select on public.users
  for select using (organization_id = public.current_org_id());

create policy users_update_self on public.users
  for update using (id = auth.uid())
  with check (id = auth.uid() and role = public.current_role());

create policy users_update_admin on public.users
  for update using (organization_id = public.current_org_id() and public.is_admin());

-- targets: leitura para toda a org; escrita para admin/pentester com MFA.
create policy targets_select on public.targets
  for select using (organization_id = public.current_org_id());

create policy targets_insert on public.targets
  for insert with check (organization_id = public.current_org_id() and public.can_write());

create policy targets_update on public.targets
  for update using (organization_id = public.current_org_id() and public.can_write());

create policy targets_delete on public.targets
  for delete using (organization_id = public.current_org_id() and public.is_admin());

-- projects: mesmo padrão de targets.
create policy projects_select on public.projects
  for select using (organization_id = public.current_org_id());

create policy projects_insert on public.projects
  for insert with check (organization_id = public.current_org_id() and public.can_write());

create policy projects_update on public.projects
  for update using (organization_id = public.current_org_id() and public.can_write());

create policy projects_delete on public.projects
  for delete using (organization_id = public.current_org_id() and public.is_admin());

-- scans: mesmo padrão. A trava de ferramenta ativa é reforçada pelo trigger
-- enforce_scan_legal_mode, não só pela RLS.
create policy scans_select on public.scans
  for select using (organization_id = public.current_org_id());

create policy scans_insert on public.scans
  for insert with check (organization_id = public.current_org_id() and public.can_write());

create policy scans_update on public.scans
  for update using (organization_id = public.current_org_id() and public.can_write());

-- findings: leitura para toda a org; escrita para admin/pentester com MFA.
create policy findings_select on public.findings
  for select using (organization_id = public.current_org_id());

create policy findings_insert on public.findings
  for insert with check (organization_id = public.current_org_id() and public.can_write());

create policy findings_update on public.findings
  for update using (organization_id = public.current_org_id() and public.can_write());

-- audit_log: imutável. Só INSERT (próprio usuário) e SELECT (admin vê tudo
-- da org; demais usuários só veem as próprias ações). Sem policy de UPDATE
-- ou DELETE — e os privilégios são revogados abaixo por defesa em profundidade.
create policy audit_log_select on public.audit_log
  for select using (
    organization_id = public.current_org_id()
    and (public.current_role() = 'admin' or user_id = auth.uid())
  );

create policy audit_log_insert on public.audit_log
  for insert with check (organization_id = public.current_org_id() and user_id = auth.uid());

revoke update, delete on public.audit_log from authenticated, anon;
