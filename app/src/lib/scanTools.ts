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
    id: "tls_scan",
    label: "Análise profunda de TLS (testssl.sh)",
    description:
      "Protocolos, cifras e vulnerabilidades conhecidas — só o handshake padrão, igual um navegador faria. Pode levar vários minutos (abre muitas conexões TLS separadas); desmarcada por padrão por causa disso.",
    slow: true,
  },
  {
    id: "subdomains",
    label: "Subdomínios públicos (crt.sh)",
    description: "Certificate Transparency — não toca o alvo diretamente.",
  },
  {
    id: "amass_passive",
    label: "Subdomínios públicos (Amass, modo passivo)",
    description: "Agrega várias fontes públicas ao mesmo tempo — só fontes de terceiros, sem tocar o alvo.",
  },
  {
    id: "dns_records",
    label: "Registros DNS (SPF/DKIM/DMARC/DNSSEC/MX)",
    description: "Consulta DNS padrão — verifica se e-mail e a zona do domínio estão configurados com segurança.",
  },
  {
    id: "whois_lookup",
    label: "WHOIS do domínio",
    description: "Expiração e servidores de nome, via consulta pública ao registrador.",
  },
  {
    id: "exposed_files",
    label: "Arquivos sensíveis expostos",
    description: ".env, .git/config, backups... checando se estão publicamente acessíveis.",
  },
  {
    id: "js_secrets_scan",
    label: "Segredos em JavaScript público",
    description: "Procura chaves de API/segredos (AWS, Stripe, etc.) em scripts públicos do mesmo domínio.",
  },
  {
    id: "storage_exposure",
    label: "Storage público (S3/GCS)",
    description: "Testa nomes de bucket comuns derivados do domínio do alvo.",
  },
  {
    id: "cookie_security",
    label: "Segurança de cookies",
    description: "Secure, HttpOnly, SameSite — nos cookies retornados pelo alvo.",
  },
  {
    id: "cors_config",
    label: "Configuração de CORS",
    description: "Testa se o alvo reflete qualquer Origin (com ou sem credenciais).",
  },
  {
    id: "hsts_mixed_content",
    label: "HSTS/preload, redirecionamento e mixed content",
    description: "Redirecionamento HTTP→HTTPS, diretivas do HSTS e referências a recursos HTTP numa página HTTPS.",
  },
  {
    id: "tech_fingerprint",
    label: "Fingerprint de tecnologia",
    description: "Identifica CMS/framework/servidor via headers e HTML público.",
  },
  {
    id: "hibp_check",
    label: "Vazamento de e-mails corporativos (Have I Been Pwned)",
    description: "Consulta a API do HIBP para prefixos comuns de e-mail do domínio. Exige HIBP_API_KEY configurada no worker.",
  },
] as const;

export type PassiveToolId = (typeof PASSIVE_TOOLS)[number]["id"];

export const PASSIVE_TOOL_IDS: readonly string[] = PASSIVE_TOOLS.map((tool) => tool.id);

// Ferramentas ATIVAS — Nível 1 (Detecção Ativa) — só disponíveis em
// projetos "ambiente_teste" com autorização confirmada, e só para role
// admin (reforçado no banco via enforce_scan_legal_mode, não só aqui).
// Cada uma corresponde a um módulo em worker/checks/ registrado em
// ACTIVE_TOOL_IDS (worker/main.py).
export const ACTIVE_TOOLS = [
  {
    id: "basic_injection_probe",
    label: "Sonda de injeção (XSS refletido / SQLi básico)",
    description: "Envia um marcador inofensivo e uma aspas simples nos parâmetros de URL existentes.",
  },
  {
    id: "port_scan",
    label: "Portas e serviços abertos (Nmap)",
    description: "TCP connect scan direto no alvo já cadastrado.",
  },
  {
    id: "content_discovery",
    label: "Descoberta de conteúdo (ffuf)",
    description: "Força bruta de diretórios/arquivos com uma wordlist pequena e curada.",
  },
  {
    id: "sqlmap_scan",
    label: "SQL Injection avançado (sqlmap)",
    description: "Payloads reais de SQLi (erro, blind, UNION) — mais abrangente que a sonda básica.",
  },
  {
    id: "xss_scan",
    label: "XSS avançado (Dalfox)",
    description: "Payloads reais de XSS refletido/armazenado nos parâmetros de URL.",
  },
  {
    id: "command_injection_scan",
    label: "Injeção de comando de SO (Commix)",
    description: "Payloads reais de injeção de comando nos parâmetros de URL.",
  },
  {
    id: "wpscan_check",
    label: "Scanner WordPress (WPScan)",
    description: "Só roda se o alvo for identificado como WordPress — plugins/temas vulneráveis, enumeração de usuários.",
  },
  {
    id: "login_bruteforce",
    label: "Credenciais fracas/padrão em login",
    description: "Testa um conjunto bem pequeno de credenciais óbvias no formulário de login, com rate limit para evitar lockout.",
  },
  {
    id: "vuln_scan_openvas",
    label: "Vulnerabilidades de infraestrutura (OpenVAS/Greenbone)",
    description: "CVEs de serviços e más configurações de SO. Exige um daemon GVM já provisionado (GVM_USERNAME/GVM_PASSWORD).",
  },
  {
    id: "api_scan_zap",
    label: "Varredura de API (OWASP ZAP)",
    description: "Só roda se uma especificação OpenAPI/Swagger for encontrada em caminhos comuns.",
  },
  {
    id: "graphql_scan",
    label: "Configuração insegura de GraphQL",
    description: "Introspection habilitada e abuso de batching — só roda se um endpoint GraphQL for encontrado.",
  },
  {
    id: "container_scan_trivy",
    label: "Vulnerabilidades em imagem de container (Trivy)",
    description: "Exige uma referência de imagem configurada (CONTAINER_SCAN_IMAGE_REF) — não se aplica à URL do alvo diretamente.",
  },
  {
    id: "kube_hunter_scan",
    label: "Más configurações de Kubernetes (kube-hunter)",
    description: "Sonda remota por portas/serviços típicos de um cluster Kubernetes exposto no host do alvo.",
  },
] as const;

export type ActiveToolId = (typeof ACTIVE_TOOLS)[number]["id"];

export const ACTIVE_TOOL_IDS: readonly string[] = ACTIVE_TOOLS.map((tool) => tool.id);

// Ferramentas de EXPLORAÇÃO CONFIRMATÓRIA — Nível 2. Além do gate de
// Ambiente de Teste (Nível 1), exigem uma segunda confirmação explícita
// + justificativa própria (exploitation_confirmed/exploitation_justification
// em `scans`), reforçada no banco via enforce_scan_legal_mode.
export const EXPLOITATION_TOOLS = [
  {
    id: "metasploit_confirm",
    label: "Metasploit Framework (confirmação de exploração)",
    description:
      "Não dispara exploits automaticamente — confirma a disponibilidade do Metasploit e orienta a condução manual da confirmação por um operador humano, dado o risco real de indisponibilizar o alvo. Ver worker/checks/metasploit_confirm.py.",
  },
] as const;

export type ExploitationToolId = (typeof EXPLOITATION_TOOLS)[number]["id"];

export const EXPLOITATION_TOOL_IDS: readonly string[] = EXPLOITATION_TOOLS.map((tool) => tool.id);
