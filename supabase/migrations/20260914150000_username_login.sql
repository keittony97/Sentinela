-- Login por usuário/senha (sem exigir e-mail do usuário final). O
-- Supabase Auth continua baseado em e-mail internamente — cada usuário
-- recebe um e-mail técnico sintético (<username>@users.sentinela.local),
-- nunca exibido nem usado para envio de mensagens reais.

alter table public.users add column username text;
alter table public.users add constraint users_username_unique unique (username);

-- Resolve username -> e-mail técnico, para o formulário de login (que só
-- pede usuário/senha) montar a chamada signInWithPassword. Security definer
-- porque essa consulta acontece ANTES de existir sessão autenticada.
create or replace function public.email_for_username(p_username text)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select email from public.users where username = p_username;
$$;

grant execute on function public.email_for_username(text) to anon, authenticated;

-- Atualiza o bootstrap de novo usuário para também gravar o username vindo
-- de raw_user_meta_data (definido na criação da conta em auth.users).
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

  insert into public.users (id, organization_id, email, username, full_name, role)
  values (
    new.id,
    v_org_id,
    new.email,
    new.raw_user_meta_data ->> 'username',
    coalesce(new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'username', new.email),
    'visualizador'
  );
  return new;
end;
$$;
