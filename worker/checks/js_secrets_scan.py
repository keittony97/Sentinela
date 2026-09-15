"""Verificação passiva de segredos expostos em JavaScript público.

Ferramenta "js_secrets_scan": busca a página inicial, extrai os arquivos
JavaScript referenciados no mesmo domínio, e procura padrões de chaves/
segredos conhecidos no conteúdo público — o mesmo que abrir "Exibir
código-fonte" e um arquivo .js no navegador. Não explora nada, não
executa o JavaScript. Disponível em qualquer modalidade legal.
"""

import re
from urllib.parse import urljoin, urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_EXPOSURE = "A01:2021 - Broken Access Control"

MAX_SCRIPTS = 15
MAX_BYTES_PER_SCRIPT = 2_000_000

SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

# (nome, regex, severidade) — padrões amplamente usados, propositalmente
# conservadores (prefixos fixos das próprias plataformas) pra reduzir
# falso positivo.
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("Chave de acesso AWS (AKIA...)", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critico"),
    ("Chave secreta AWS", re.compile(r'aws_secret_access_key["\']?\s*[:=]\s*["\'][A-Za-z0-9/+=]{40}["\']', re.I), "critico"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b"), "critico"),
    ("Stripe restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{16,}\b"), "critico"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "alto"),
    ("Chave privada RSA/PEM", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "critico"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "alto"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "alto"),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b"), "alto"),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "alto"),
    ("JWT hardcoded (payload embutido no código)", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medio"),
]


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    log("info", f"Buscando página inicial de {url} para extrair scripts")

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
                "impact": "Não foi possível buscar scripts públicos pois a conexão falhou.",
                "recommendation": "Verifique se a URL está correta e acessível a partir do worker.",
                "reference_links": [],
                "evidence": {"url": url, "error": str(exc)},
            }
        )
        return logs, findings

    script_srcs = SCRIPT_SRC_PATTERN.findall(resp.text)
    same_origin_scripts = []
    for src in script_srcs:
        absolute = urljoin(str(resp.url), src)
        if urlparse(absolute).hostname == hostname:
            same_origin_scripts.append(absolute)

    same_origin_scripts = list(dict.fromkeys(same_origin_scripts))[:MAX_SCRIPTS]
    log("info", f"{len(script_srcs)} script(s) referenciados, {len(same_origin_scripts)} do mesmo domínio (limite {MAX_SCRIPTS}) serão baixados")

    scripts_scanned = 0
    matches_found: list[dict] = []

    for script_url in same_origin_scripts:
        try:
            script_resp = httpx.get(script_url, timeout=15, follow_redirects=True)
            content = script_resp.text[:MAX_BYTES_PER_SCRIPT]
        except Exception as exc:  # noqa: BLE001
            log("warning", f"Falha ao baixar {script_url}: {exc}")
            continue

        scripts_scanned += 1
        for name, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                snippet = match.group(0)
                masked = snippet[:6] + "…" + snippet[-4:] if len(snippet) > 12 else "…"
                matches_found.append(
                    {"pattern": name, "severity": severity, "script_url": script_url, "masked_match": masked}
                )
                log("warning", f"Padrão '{name}' encontrado em {script_url}")

    log("info", f"{scripts_scanned} script(s) baixado(s) e analisado(s)")

    if matches_found:
        # Um finding por padrão único encontrado, agregando as URLs onde apareceu.
        by_pattern: dict[str, dict] = {}
        for m in matches_found:
            entry = by_pattern.setdefault(m["pattern"], {"severity": m["severity"], "occurrences": []})
            entry["occurrences"].append({"script_url": m["script_url"], "masked_match": m["masked_match"]})

        for pattern_name, data in by_pattern.items():
            urls_str = ", ".join(sorted({o["script_url"] for o in data["occurrences"]}))
            findings.append(
                {
                    "severity": data["severity"],
                    "title": f"Possível segredo exposto em JavaScript público: {pattern_name}",
                    "cwe": "CWE-798",
                    "owasp_category": OWASP_EXPOSURE,
                    "description": f"Encontrado padrão compatível com '{pattern_name}' em script(s) público(s): {urls_str}.",
                    "impact": "Chaves/segredos hardcoded em JavaScript público ficam visíveis a qualquer visitante — podem ser usadas para acessar serviços de terceiros (cloud, pagamentos, e-mail) em nome da organização, gerando custo ou vazamento de dados.",
                    "recommendation": "Revogar/rotacionar imediatamente a credencial exposta, e mover segredos para variáveis de ambiente/backend, nunca embutidos em código enviado ao navegador.",
                    "reference_links": ["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
                    "evidence": {"pattern": pattern_name, "occurrences": data["occurrences"]},
                }
            )
    else:
        log("info", "Nenhum padrão de segredo conhecido encontrado nos scripts analisados.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum segredo óbvio encontrado em JavaScript público",
                "cwe": None,
                "owasp_category": None,
                "description": f"{scripts_scanned} script(s) do domínio {hostname} foram analisados sem encontrar padrões de chave/segredo conhecidos.",
                "impact": "Nenhum — não garante ausência total (padrões customizados ou ofuscação podem escapar da detecção), mas nenhum indício óbvio foi encontrado.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"scripts_scanned": scripts_scanned},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
