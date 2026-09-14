"""Verificação passiva de portas expostas via Shodan.

Ferramenta "exposed_ports": consulta o Shodan (banco de dados de scans já
feitos por terceiros), nunca faz port scan direto no alvo — 100% passivo.
Requer SHODAN_API_KEY configurada em worker/.env; sem ela, registra um
achado informativo explicando que a verificação foi pulada, em vez de
falhar o scan inteiro.
"""

import os
import socket
from urllib.parse import urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5900: "VNC",
    2375: "Docker (API sem TLS)",
}


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o host de {url}")
        return logs, findings

    try:
        ip = socket.gethostbyname(hostname)
        log("info", f"{hostname} resolve para {ip}")
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao resolver DNS de {hostname}: {exc}")
        return logs, findings

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        log("warning", "SHODAN_API_KEY não configurada — verificação de portas via Shodan pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação de portas via Shodan não executada (sem API key configurada)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'exposed_ports' precisa de uma SHODAN_API_KEY em worker/.env para consultar o Shodan.",
                "impact": "Nenhum — apenas informativo. Esta verificação simplesmente não rodou.",
                "recommendation": "Se quiser essa verificação, crie uma conta em shodan.io e configure SHODAN_API_KEY em worker/.env.",
                "reference_links": ["https://www.shodan.io/"],
                "evidence": {"host": hostname, "ip": ip},
            }
        )
        return logs, findings

    log("info", f"Consultando Shodan (serviço passivo) para {ip}")
    try:
        resp = httpx.get(
            f"https://api.shodan.io/shodan/host/{ip}", params={"key": api_key}, timeout=20
        )
        if resp.status_code == 404:
            log("info", "Shodan não tem informações indexadas para este IP.")
            findings.append(
                {
                    "severity": "informativo",
                    "title": "Nenhuma informação indexada no Shodan para este IP",
                    "cwe": None,
                    "owasp_category": None,
                    "description": f"O Shodan não tem nenhum scan indexado para {ip}.",
                    "impact": "Nenhum.",
                    "recommendation": "Nenhuma ação necessária.",
                    "reference_links": ["https://www.shodan.io/"],
                    "evidence": {"host": hostname, "ip": ip},
                }
            )
            return logs, findings
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao consultar Shodan: {exc}")
        return logs, findings

    ports = sorted(data.get("ports", []))
    log("info", f"Shodan reporta {len(ports)} porta(s) aberta(s): {ports}")

    for port in ports:
        if port not in RISKY_PORTS:
            continue
        service = RISKY_PORTS[port]
        log("warning", f"Porta {port} ({service}) exposta publicamente")
        findings.append(
            {
                "severity": "alto",
                "title": f"Porta {port} ({service}) exposta publicamente",
                "cwe": "CWE-200",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "description": f"O Shodan indexou a porta {port} ({service}) aberta em {ip} ({hostname}).",
                "impact": f"Serviços como {service} não deveriam estar acessíveis diretamente pela internet — aumentam a superfície de ataque para brute-force, exploits conhecidos ou acesso não autorizado a dados.",
                "recommendation": f"Restringir o acesso à porta {port} via firewall/security group (VPN ou IP allowlist), ou desativar o serviço se não for necessário publicamente.",
                "reference_links": ["https://www.shodan.io/"],
                "evidence": {"host": hostname, "ip": ip, "port": port, "shodan_data": data.get("data", [])[:3]},
            }
        )

    findings.append(
        {
            "severity": "informativo",
            "title": f"{len(ports)} porta(s) aberta(s) indexadas pelo Shodan",
            "cwe": None,
            "owasp_category": None,
            "description": f"Lista completa de portas indexadas para {ip}: {ports}",
            "impact": "Mapeamento de superfície de ataque.",
            "recommendation": "Revisar se todas as portas abertas são intencionais.",
            "reference_links": ["https://www.shodan.io/"],
            "evidence": {"host": hostname, "ip": ip, "ports": ports},
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
