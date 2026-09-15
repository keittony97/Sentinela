"""Fingerprint passivo de tecnologia (CMS/framework/servidor).

Ferramenta "tech_fingerprint": só faz uma requisição GET normal e inspeciona
headers + HTML público em busca de padrões conhecidos (o mesmo que
"Exibir código-fonte" no navegador mostraria) — disponível em qualquer
modalidade legal. Achados aqui alimentam a decisão de disponibilizar
ferramentas específicas de CMS (ex: WPScan) no modo "Ambiente de Teste".
"""

import re
from urllib.parse import urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"

# (nome, regex que casa em headers+html combinados, onde procurar versão)
CMS_SIGNATURES: list[tuple[str, re.Pattern, re.Pattern | None]] = [
    ("WordPress", re.compile(r"wp-content|wp-includes|/wp-json/", re.I), re.compile(r'content="WordPress ([\d.]+)"', re.I)),
    ("Joomla", re.compile(r"/media/jui/|Joomla!", re.I), re.compile(r'content="Joomla! ([\d.]+)"', re.I)),
    ("Drupal", re.compile(r"Drupal\.settings|/sites/default/files", re.I), re.compile(r'content="Drupal ([\d.]+)"', re.I)),
    ("Magento", re.compile(r"Mage\.Cookies|/skin/frontend/", re.I), None),
    ("Shopify", re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I), None),
]

FRAMEWORK_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("Next.js", re.compile(r"__NEXT_DATA__|/_next/static/", re.I)),
    ("React", re.compile(r"data-reactroot|react-dom", re.I)),
    ("Angular", re.compile(r"ng-version=", re.I)),
    ("Vue.js", re.compile(r"data-v-[0-9a-f]{6,}|__VUE__", re.I)),
    ("Laravel", re.compile(r"laravel_session", re.I)),
    ("Django", re.compile(r"csrfmiddlewaretoken", re.I)),
    ("ASP.NET", re.compile(r"__VIEWSTATE|ASP\.NET_SessionId", re.I)),
    ("Ruby on Rails", re.compile(r"_rails_session|csrf-param", re.I)),
]

SERVER_VERSION_PATTERN = re.compile(r"^([a-zA-Z][\w.-]*)/([\d][\w.-]*)")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", f"Fazendo fingerprint de tecnologia em {url}")

    try:
        resp = httpx.get(url, follow_redirects=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao conectar: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível conectar ao alvo",
                "cwe": None,
                "owasp_category": None,
                "description": f"A tentativa de GET em {url} falhou: {exc}",
                "impact": "Não foi possível identificar a stack tecnológica pois a conexão falhou.",
                "recommendation": "Verifique se a URL está correta e acessível a partir do worker.",
                "reference_links": [],
                "evidence": {"url": url, "error": str(exc)},
            }
        )
        return logs, findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    html = resp.text
    combined = html + " " + " ".join(headers.values())

    detected: list[dict] = []

    for name, pattern, version_pattern in CMS_SIGNATURES:
        if pattern.search(combined):
            version = None
            if version_pattern:
                m = version_pattern.search(html)
                if m:
                    version = m.group(1)
            detected.append({"category": "CMS", "name": name, "version": version})
            log("info", f"CMS detectado: {name}" + (f" v{version}" if version else ""))

    for name, pattern in FRAMEWORK_SIGNATURES:
        if pattern.search(combined):
            detected.append({"category": "framework", "name": name, "version": None})
            log("info", f"Framework detectado: {name}")

    powered_by = headers.get("x-powered-by")
    if powered_by:
        detected.append({"category": "x-powered-by", "name": powered_by, "version": None})
        log("info", f"Header X-Powered-By: {powered_by}")

    server = headers.get("server")
    server_version_leak = None
    if server:
        m = SERVER_VERSION_PATTERN.match(server)
        if m:
            server_version_leak = server

    if not detected and not server and not powered_by:
        log("info", "Nenhuma tecnologia identificável via headers/HTML público.")

    if detected:
        findings.append(
            {
                "severity": "informativo",
                "title": f"Tecnologias identificadas: {', '.join(sorted({d['name'] for d in detected}))}",
                "cwe": None,
                "owasp_category": None,
                "description": "Fingerprint passivo (headers + HTML público) identificou as seguintes tecnologias: "
                + ", ".join(f"{d['name']}" + (f" v{d['version']}" if d["version"] else "") for d in detected),
                "impact": "Mapeamento de superfície de ataque — conhecer a stack ajuda a priorizar quais ferramentas específicas (ex: WPScan para WordPress) usar em Ambiente de Teste.",
                "recommendation": "Nenhuma ação obrigatória; se a política de segurança exigir, considerar ofuscar sinais óbvios de tecnologia (ex: remover meta generator, X-Powered-By).",
                "reference_links": [],
                "evidence": {"url": url, "detected": detected},
            }
        )

    if server_version_leak or powered_by:
        exposed = ", ".join(filter(None, [server_version_leak, powered_by]))
        findings.append(
            {
                "severity": "baixo",
                "title": "Versão de tecnologia exposta em headers HTTP",
                "cwe": "CWE-200",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"Os headers de {url} expõem detalhes de versão: {exposed}.",
                "impact": "Facilita o reconhecimento do atacante sobre versões específicas com vulnerabilidades conhecidas (CVEs).",
                "recommendation": "Configurar o servidor/aplicação para omitir ou generalizar headers como 'Server' e 'X-Powered-By'.",
                "reference_links": [],
                "evidence": {"server": server, "x_powered_by": powered_by},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
