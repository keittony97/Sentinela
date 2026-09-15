"""Varredura ATIVA de más configurações de Kubernetes via kube-hunter.

Ferramenta "kube_hunter_scan": ATIVA — roda kube-hunter em modo remoto
(`--remote <host>`), que sonda portas/serviços tipicamente associados a
um cluster Kubernetes (API server, kubelet, etcd, dashboard) contra o
host do alvo. Só encontra algo se o alvo de fato expuser esses serviços
publicamente; caso contrário, o resultado é "nenhum serviço Kubernetes
encontrado", o que é o esperado pra maioria dos alvos web comuns. Só
disponível em projetos "Ambiente de Teste" autorizados (Nível 1 —
Detecção Ativa).
"""

import json
import shutil
import subprocess
from urllib.parse import urlparse

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"

SEVERITY_MAP = {"high": "alto", "medium": "medio", "low": "baixo"}


def _find_kube_hunter() -> str | None:
    return shutil.which("kube-hunter")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o host de {url}")
        return logs, findings

    binary = _find_kube_hunter()
    if not binary:
        log("warning", "kube-hunter não encontrado nesta máquina — verificação pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Varredura via kube-hunter não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'kube_hunter_scan' precisa do binário 'kube-hunter' disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo.",
                "recommendation": "Instalar o kube-hunter na máquina/container do worker (`pip install kube-hunter`).",
                "reference_links": ["https://github.com/aquasecurity/kube-hunter"],
                "evidence": {"host": hostname},
            }
        )
        return logs, findings

    log("info", f"Rodando kube-hunter em modo remoto contra {hostname}")
    try:
        result = subprocess.run(
            [binary, "--remote", hostname, "--report", "json"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log("error", "kube-hunter excedeu o tempo limite (180s).")
        return logs, findings
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao executar kube-hunter: {exc}")
        return logs, findings

    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        log("warning", "Saída do kube-hunter não é JSON válido (comum quando nenhum serviço K8s é encontrado).")
        data = {}

    vulnerabilities = data.get("vulnerabilities", []) or []
    services = data.get("services", []) or []

    log("info", f"kube-hunter encontrou {len(services)} serviço(s) e {len(vulnerabilities)} vulnerabilidade(s) tipo-K8s")

    for vuln in vulnerabilities:
        severity = SEVERITY_MAP.get((vuln.get("severity") or "").lower(), "medio")
        findings.append(
            {
                "severity": severity,
                "title": vuln.get("vulnerability", "Vulnerabilidade Kubernetes detectada"),
                "cwe": None,
                "owasp_category": OWASP_MISCONFIG,
                "description": (vuln.get("description", "") or "")[:2000],
                "impact": vuln.get("evidence", "Ver detalhes na descrição.")[:1000],
                "recommendation": "Consultar a documentação do kube-hunter para orientação de correção específica desta vulnerabilidade.",
                "reference_links": ["https://github.com/aquasecurity/kube-hunter"],
                "evidence": {"host": hostname, "raw": vuln},
            }
        )

    if services and not vulnerabilities:
        findings.append(
            {
                "severity": "medio",
                "title": f"{len(services)} serviço(s) tipo-Kubernetes exposto(s) publicamente",
                "cwe": "CWE-200",
                "owasp_category": OWASP_MISCONFIG,
                "description": "kube-hunter detectou serviços associados a Kubernetes acessíveis publicamente: "
                + ", ".join(s.get("service", "?") for s in services),
                "impact": "Serviços de cluster (API server, kubelet, dashboard, etcd) expostos publicamente ampliam muito a superfície de ataque de infraestrutura.",
                "recommendation": "Restringir o acesso a esses serviços via firewall/VPC — nenhum componente de plano de controle do Kubernetes deveria estar acessível pela internet pública.",
                "reference_links": ["https://github.com/aquasecurity/kube-hunter"],
                "evidence": {"host": hostname, "services": services},
            }
        )

    if not services and not vulnerabilities:
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum serviço Kubernetes encontrado no alvo",
                "cwe": None,
                "owasp_category": None,
                "description": f"kube-hunter não encontrou portas/serviços tipicamente associados a Kubernetes em {hostname}.",
                "impact": "Nenhum — resultado esperado para a maioria dos alvos web que não são clusters Kubernetes expostos diretamente.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"host": hostname},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
