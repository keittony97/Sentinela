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
    id: "exposed_ports",
    label: "Portas expostas (Shodan)",
    description: "Consulta passiva ao Shodan. Requer SHODAN_API_KEY configurada no worker.",
  },
  {
    id: "storage_exposure",
    label: "Storage público (S3/GCS)",
    description: "Testa nomes de bucket comuns derivados do domínio do alvo.",
  },
] as const;

export type PassiveToolId = (typeof PASSIVE_TOOLS)[number]["id"];

export const PASSIVE_TOOL_IDS: readonly string[] = PASSIVE_TOOLS.map((tool) => tool.id);
