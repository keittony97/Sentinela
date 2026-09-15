"""Varredura ATIVA de API via OWASP ZAP (a partir de spec OpenAPI/Swagger).

Ferramenta "api_scan_zap": ATIVA — só faz sentido se o alvo expõe uma
especificação OpenAPI/Swagger; esta ferramenta primeiro tenta descobrir
uma automaticamente em caminhos bem conhecidos (o mesmo que um navegador
acessando essas URLs faria) e só então dispara o `zap-api-scan.py`
(script oficial do ZAP que sobe um daemon ZAP temporário e testa cada
operação da API). Só disponível em projetos "Ambiente de Teste"
autorizados (Nível 1 — Detecção Ativa).
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urljoin

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_API = "A05:2021 - Security Misconfiguration"

COMMON_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
]

RISK_TO_SEVERITY = {"High": "alto", "Medium": "medio", "Low": "baixo", "Informational": "informativo"}


def _discover_spec(base_url: str, log) -> str | None:
    for path in COMMON_SPEC_PATHS:
        candidate = urljoin(base_url, path)
        try:
            resp = httpx.get(candidate, timeout=10, follow_redirects=True)
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            body_start = resp.text.lstrip()[:20].lower()
            looks_like_spec = (
                "swagger" in content_type
                or "openapi" in content_type
                or body_start.startswith("{") and ('"openapi"' in resp.text[:500].lower() or '"swagger"' in resp.text[:500].lower())
            )
            if looks_like_spec:
                log("info", f"Especificação OpenAPI/Swagger encontrada em {candidate}")
                return candidate
    return None


def _find_zap_script() -> str | None:
    return shutil.which("zap-api-scan.py")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", f"Procurando especificação OpenAPI/Swagger em caminhos comuns de {url}")
    spec_url = _discover_spec(url, log)

    if not spec_url:
        log("info", "Nenhuma especificação OpenAPI/Swagger encontrada nos caminhos comuns testados.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Varredura de API via ZAP não aplicável — nenhuma spec OpenAPI/Swagger encontrada",
                "cwe": None,
                "owasp_category": None,
                "description": f"Testados {len(COMMON_SPEC_PATHS)} caminhos comuns a partir de {url} sem encontrar uma especificação OpenAPI/Swagger.",
                "impact": "Nenhum — esta ferramenta depende de uma especificação de API descoberta automaticamente.",
                "recommendation": "Se a API tiver uma especificação em um caminho não padrão, informar a URL exata da spec manualmente para uma varredura dedicada.",
                "reference_links": [],
                "evidence": {"paths_tested": COMMON_SPEC_PATHS},
            }
        )
        return logs, findings

    zap_script = _find_zap_script()
    if not zap_script:
        log("warning", "zap-api-scan.py não encontrado nesta máquina — varredura de API pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Varredura de API via ZAP não executada (zap-api-scan.py não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": f"Uma especificação OpenAPI/Swagger foi encontrada em {spec_url}, mas o script 'zap-api-scan.py' não está disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo. A spec foi localizada; falta só a ferramenta pra escaneá-la.",
                "recommendation": "Instalar o OWASP ZAP na máquina/container do worker (https://www.zaproxy.org/download/) — o script zap-api-scan.py vem junto com a instalação completa.",
                "reference_links": ["https://www.zaproxy.org/docs/docker/api-scan/"],
                "evidence": {"spec_url": spec_url},
            }
        )
        return logs, findings

    with tempfile.TemporaryDirectory() as tmp_dir:
        report_path = Path(tmp_dir) / "zap-report.json"
        log("info", f"Rodando zap-api-scan.py contra {spec_url}")
        try:
            result = subprocess.run(
                [
                    zap_script,
                    "-t", spec_url,
                    "-f", "openapi",
                    "-J", str(report_path),
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            log("error", "zap-api-scan.py excedeu o tempo limite (600s).")
            return logs, findings
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao executar zap-api-scan.py: {exc}")
            return logs, findings

        for line in result.stdout.splitlines():
            if line.strip():
                log("info", line.strip()[:300])

        if not report_path.exists():
            log("error", "zap-api-scan.py não gerou relatório JSON.")
            return logs, findings

        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            log("error", f"Falha ao interpretar relatório JSON do ZAP: {exc}")
            return logs, findings

    alerts = []
    for site in report.get("site", []):
        alerts.extend(site.get("alerts", []))

    log("info", f"ZAP encontrou {len(alerts)} tipo(s) de alerta")

    for alert in alerts:
        risk = alert.get("riskdesc", "").split(" ")[0]
        severity = RISK_TO_SEVERITY.get(risk, "informativo")
        instances = alert.get("instances", [])
        findings.append(
            {
                "severity": severity,
                "title": alert.get("name", "Alerta ZAP"),
                "cwe": f"CWE-{alert.get('cweid')}" if alert.get("cweid") and alert.get("cweid") != "-1" else None,
                "owasp_category": OWASP_API,
                "description": (alert.get("desc", "") or "")[:2000],
                "impact": (alert.get("otherinfo", "") or f"Risco {risk} segundo o ZAP.")[:1000],
                "recommendation": (alert.get("solution", "") or "Consultar a documentação do ZAP para este alerta.")[:1000],
                "reference_links": [l for l in (alert.get("reference", "") or "").splitlines() if l.strip()],
                "evidence": {"spec_url": spec_url, "instances": [i.get("uri") for i in instances][:20]},
            }
        )

    if not alerts:
        findings.append(
            {
                "severity": "informativo",
                "title": "ZAP não encontrou alertas na API",
                "cwe": None,
                "owasp_category": None,
                "description": f"zap-api-scan.py testou a especificação {spec_url} sem gerar alertas.",
                "impact": "Nenhum indício encontrado nesta verificação.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"spec_url": spec_url},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
