-- Cabeçalho de conformidade e rastreabilidade do relatório (requisito do
-- usuário, registrado em CLAUDE.md). Texto fica no banco, não hardcoded
-- no frontend, pra poder ser revisado pelo jurídico da organização antes
-- de entrar em produção. "{{modalidade}}" no texto é substituído em
-- tempo de geração pelo rótulo da modalidade legal do projeto.
create table public.report_compliance_templates (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null unique references public.organizations (id) on delete cascade,
  methodology_statement text not null,
  lgpd_note text not null,
  updated_at timestamptz not null default now()
);

create trigger trg_report_compliance_templates_updated_at
before update on public.report_compliance_templates
for each row execute function public.set_updated_at();

alter table public.report_compliance_templates enable row level security;

create policy report_compliance_templates_select on public.report_compliance_templates
  for select using (organization_id = public.current_org_id());

create policy report_compliance_templates_update on public.report_compliance_templates
  for update using (organization_id = public.current_org_id() and public.is_admin());

create policy report_compliance_templates_insert on public.report_compliance_templates
  for insert with check (organization_id = public.current_org_id() and public.is_admin());

-- Semente com o texto padrão para a organização já existente. Se uma
-- organização nova for criada sem linha aqui, o gerador de PDF cai para
-- um texto padrão embutido no código (ver ProjectReportDocument.tsx).
insert into public.report_compliance_templates (organization_id, methodology_statement, lgpd_note)
select
  id,
  'Este relatório documenta os resultados de uma verificação de segurança conduzida estritamente sob a modalidade legal declarada para o projeto ({{modalidade}}). Nenhum procedimento intrusivo ou exploratório foi realizado além do estritamente necessário para confirmar a existência de cada vulnerabilidade relatada — não houve extração, cópia ou manipulação de dados além do mínimo indispensável para evidenciar a falha encontrada.',
  'Nota de conformidade com a LGPD (Lei nº 13.709/2018): esta verificação pode ter exposto, incidentalmente, dados pessoais durante a confirmação de vulnerabilidades (art. 6º — princípios da necessidade e da minimização, e art. 46 — medidas de segurança exigidas do controlador/operador). Qualquer dado pessoal eventualmente visualizado durante o teste foi tratado exclusivamente para fins de confirmação e documentação da falha identificada, sem armazenamento além do estritamente necessário para a elaboração deste relatório. Como recomendação técnica — não como afirmação jurídica categórica — sugere-se que a organização responsável pelo alvo avalie, junto ao seu Encarregado de Dados (DPO) e à área jurídica, a eventual necessidade de comunicação à Autoridade Nacional de Proteção de Dados (ANPD) e aos titulares dos dados, conforme art. 48 da LGPD.'
from public.organizations
on conflict (organization_id) do nothing;
