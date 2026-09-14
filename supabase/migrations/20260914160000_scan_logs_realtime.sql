-- Log de execução de scan em tempo real (separado do relatório de
-- findings). Só o worker (service_role, bypassa RLS) escreve aqui — o
-- cliente só lê, via Supabase Realtime.

create table public.scan_logs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete restrict,
  scan_id uuid not null references public.scans (id) on delete cascade,
  tool text not null,
  level text not null default 'info' check (level in ('info', 'warning', 'error')),
  message text not null,
  created_at timestamptz not null default now()
);

create index idx_scan_logs_scan on public.scan_logs (scan_id, created_at);
create index idx_scan_logs_organization on public.scan_logs (organization_id);

alter table public.scan_logs enable row level security;

create policy scan_logs_select on public.scan_logs
  for select using (organization_id = public.current_org_id());

-- Broadcast de mudanças (Postgres Changes) pra tela de execução de scan ao
-- vivo: log linha a linha, status do scan, e findings aparecendo.
alter publication supabase_realtime add table public.scan_logs;
alter publication supabase_realtime add table public.scans;
alter publication supabase_realtime add table public.findings;
