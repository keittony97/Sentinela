"""Varredura ATIVA de vulnerabilidades em imagens de container via Trivy.

Ferramenta "container_scan_trivy": ATIVA por natureza (dispara download/
análise de uma imagem real), mas com uma limitação estrutural importante:
Trivy escaneia uma IMAGEM de container (ex: "nginx:1.25") ou um
filesystem/repositório — não uma URL de aplicação web. Não há como
derivar de forma confiável qual imagem Docker um alvo web usa só a
partir da sua URL. Por isso, esta ferramenta só roda de fato se uma
imagem for informada explicitamente via a variável de ambiente
CONTAINER_SCAN_IMAGE_REF (configuração futura, não vinculada ao alvo);
caso contrário, registra um achado informativo explicando a limitação em
vez de fingir uma cobertura que não existe. Só disponível em projetos
"Ambiente de Teste" autorizados (Nível 1 — Detecção Ativa).
"""

import json
import os
import shutil
import subprocess

OWASP_VULN_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"

SEVERITY_MAP = {"CRITICAL": "critico", "HIGH": "alto", "MEDIUM": "medio", "LOW": "baixo", "UNKNOWN": "informativo"}


def _find_trivy() -> str | None:
    return shutil.which("trivy")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    image_ref = os.environ.get("CONTAINER_SCAN_IMAGE_REF")
    if not image_ref:
        log("info", "CONTAINER_SCAN_IMAGE_REF não configurado — Trivy não se aplica a uma URL de aplicação web diretamente.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Varredura de container via Trivy não aplicável (alvo é uma URL, não uma imagem)",
                "cwe": None,
                "owasp_category": None,
                "description": f"Trivy escaneia imagens de container (ex: 'nginx:1.25'), não a URL do alvo ({url}). Não há uma imagem associada configurada (CONTAINER_SCAN_IMAGE_REF).",
                "impact": "Nenhum — esta ferramenta simplesmente não se aplica ao modelo atual de 'alvo = URL' sem informação adicional.",
                "recommendation": "Se a organização quiser escanear as imagens de container que compõem este alvo, configurar CONTAINER_SCAN_IMAGE_REF com a referência da imagem (registry/nome:tag) num scan dedicado.",
                "reference_links": ["https://aquasecurity.github.io/trivy/"],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    trivy_binary = _find_trivy()
    if not trivy_binary:
        log("warning", "Trivy não encontrado nesta máquina — verificação pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Varredura via Trivy não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'container_scan_trivy' precisa do binário 'trivy' disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo.",
                "recommendation": "Instalar o Trivy na máquina/container do worker (https://aquasecurity.github.io/trivy/).",
                "reference_links": ["https://aquasecurity.github.io/trivy/"],
                "evidence": {"image_ref": image_ref},
            }
        )
        return logs, findings

    log("info", f"Rodando Trivy contra a imagem {image_ref}")
    try:
        result = subprocess.run(
            [trivy_binary, "image", "--format", "json", "--quiet", image_ref],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        log("error", "Trivy excedeu o tempo limite (300s).")
        return logs, findings
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao executar Trivy: {exc}")
        return logs, findings

    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError as exc:
        log("error", f"Falha ao interpretar saída JSON do Trivy: {exc}")
        return logs, findings

    vulnerabilities = []
    for target in data.get("Results", []):
        vulnerabilities.extend(target.get("Vulnerabilities", []) or [])

    log("info", f"Trivy encontrou {len(vulnerabilities)} vulnerabilidade(s) na imagem {image_ref}")

    by_severity_count: dict[str, int] = {}
    for vuln in vulnerabilities:
        sev = SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "informativo")
        by_severity_count[sev] = by_severity_count.get(sev, 0) + 1
        if sev in ("critico", "alto"):
            findings.append(
                {
                    "severity": sev,
                    "title": f"{vuln.get('VulnerabilityID', '?')} em {vuln.get('PkgName', '?')} ({image_ref})",
                    "cwe": None,
                    "owasp_category": OWASP_VULN_COMPONENTS,
                    "description": (vuln.get("Description", "") or "")[:2000],
                    "impact": f"Severidade {vuln.get('Severity')} — pacote {vuln.get('PkgName')} versão instalada {vuln.get('InstalledVersion')}.",
                    "recommendation": f"Atualizar '{vuln.get('PkgName')}' para a versão corrigida ({vuln.get('FixedVersion') or 'ver aviso do fornecedor'}).",
                    "reference_links": vuln.get("References", [])[:5],
                    "evidence": {"image": image_ref, "vulnerability_id": vuln.get("VulnerabilityID"), "package": vuln.get("PkgName")},
                }
            )

    findings.append(
        {
            "severity": "informativo",
            "title": f"{len(vulnerabilities)} vulnerabilidade(s) encontradas na imagem {image_ref}",
            "cwe": None,
            "owasp_category": None,
            "description": f"Resumo por severidade: {by_severity_count}",
            "impact": "Ver achados individuais de severidade crítica/alta acima, se houver.",
            "recommendation": "Manter a imagem base e os pacotes instalados atualizados regularmente.",
            "reference_links": [],
            "evidence": {"image": image_ref, "counts": by_severity_count},
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
