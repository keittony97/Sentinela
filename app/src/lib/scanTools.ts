// Ferramentas passivas disponíveis no modo "Verificação Externa" — todas
// is_active_tool=false. Cada uma corresponde a um módulo em
// worker/checks/ registrado em TOOL_RUNNERS (worker/main.py). Manter as
// duas listas em sincronia ao adicionar uma nova ferramenta.
export const PASSIVE_TOOLS = [
  {
    id: "headers_tls",
    label: "Headers de segurança + TLS",
    description: "HSTS, CSP, X-Frame-Options... e validade do certificado.",
  },
  {
    id: "subdomains",
    label: "Subdomínios públicos",
    description: "Certificate Transparency (crt.sh) — não toca o alvo diretamente.",
  },
  {
    id: "exposed_files",
    label: "Arquivos sensíveis expostos",
    description: ".env, .git/config, backups... checando se estão publicamente acessíveis.",
  },
  {
    id: "port_scan",
    label: "Portas e serviços abertos (Nmap)",
    description: "TCP connect scan direto no alvo já cadastrado — sem depender de dados de terceiros.",
  },
  {
    id: "storage_exposure",
    label: "Storage público (S3/GCS)",
    description: "Testa nomes de bucket comuns derivados do domínio do alvo.",
  },
] as const;

export type PassiveToolId = (typeof PASSIVE_TOOLS)[number]["id"];

export const PASSIVE_TOOL_IDS: readonly string[] = PASSIVE_TOOLS.map((tool) => tool.id);

// Ferramentas ATIVAS — só disponíveis em projetos "ambiente_teste" com
// autorização confirmada, e só para role admin (reforçado no banco via
// enforce_scan_legal_mode, não só aqui). Cada uma corresponde a um módulo
// em worker/checks/ registrado em ACTIVE_TOOL_IDS (worker/main.py).
export const ACTIVE_TOOLS = [
  {
    id: "basic_injection_probe",
    label: "Sonda de injeção (XSS refletido / SQLi básico)",
    description:
      "Envia um marcador inofensivo e uma aspas simples nos parâmetros de URL existentes. Ferramenta ativa — só Admin, só em Ambiente de Teste autorizado.",
  },
] as const;

export type ActiveToolId = (typeof ACTIVE_TOOLS)[number]["id"];

export const ACTIVE_TOOL_IDS: readonly string[] = ACTIVE_TOOLS.map((tool) => tool.id);
