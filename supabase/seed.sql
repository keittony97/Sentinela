-- Organização única do MVP. O primeiro admin pode renomear depois
-- (update permitido só para role 'admin' com MFA — ver policy org_update_admin).
insert into public.organizations (name)
values ('Sentinela corp')
on conflict do nothing;
