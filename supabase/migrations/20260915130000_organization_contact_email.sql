-- Contato comercial da organização (nome já existia via public.organizations.name).
-- Sem policy nova: a policy org_update_admin já cobre UPDATE de qualquer
-- coluna desta tabela (admin com MFA); org_select já cobre leitura por
-- qualquer membro da organização.
alter table public.organizations
  add column contact_email text;
