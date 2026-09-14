-- Fase 7 — "permissões mais finas por perfil" pra ferramentas ativas:
-- além do gate de modalidade legal (Fase 2), só Admin pode disparar um
-- scan com is_active_tool=true — Pentester continua liberado pra tudo
-- que é passivo, mas ferramentas ativas (SQLi/XSS/etc) ficam reservadas
-- ao papel mais confiável. Também registra automaticamente no audit_log
-- toda vez que uma ferramenta ativa é disparada (só no INSERT, não a
-- cada UPDATE de status feito pelo worker).
create or replace function public.enforce_scan_legal_mode()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_legal_mode public.legal_mode;
  v_authorized boolean;
  v_org_id uuid;
  v_triggered_by_role public.user_role;
begin
  select legal_mode, authorization_confirmed, organization_id
    into v_legal_mode, v_authorized, v_org_id
    from public.projects
    where id = new.project_id;

  if new.is_active_tool then
    if v_legal_mode is distinct from 'ambiente_teste' or v_authorized is not true then
      raise exception 'Ferramentas ativas só podem ser executadas em projetos na modalidade "Ambiente de Teste" com autorização confirmada.';
    end if;

    select role into v_triggered_by_role from public.users where id = new.triggered_by;
    if v_triggered_by_role is distinct from 'admin' then
      raise exception 'Ferramentas ativas só podem ser disparadas por um Admin (perfil atual: %).', coalesce(v_triggered_by_role::text, 'desconhecido');
    end if;

    if tg_op = 'INSERT' then
      insert into public.audit_log (organization_id, user_id, action, entity_type, entity_id, metadata)
      values (
        v_org_id,
        new.triggered_by,
        'active_scan_triggered',
        'scan',
        new.id,
        jsonb_build_object('project_id', new.project_id, 'tools_used', new.tools_used)
      );
    end if;
  end if;

  return new;
end;
$$;
