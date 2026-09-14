-- Com REPLICA IDENTITY padrão (só chave primária), um UPDATE que só muda
-- `status`/`started_at`/`finished_at` não inclui `organization_id` no WAL
-- — e a Realtime precisa dessa coluna pra avaliar a policy de RLS
-- (organization_id = current_org_id()), então descarta o evento
-- silenciosamente. REPLICA IDENTITY FULL inclui a linha inteira em toda
-- mudança, resolvendo isso pra UPDATE/DELETE.
alter table public.scans replica identity full;
alter table public.scan_logs replica identity full;
alter table public.findings replica identity full;
