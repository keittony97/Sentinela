"""Reconhecimento de portas e serviços via Nmap.

Ferramenta "port_scan": substitui a abordagem via Shodan/Censys (Fase 5) —
roda um TCP connect scan (-sT, não precisa de privilégio elevado nem de
driver de captura de pacotes) direto contra o alvo já cadastrado no
sistema. Vantagens sobre um serviço de terceiros: não depende de dados
indexados que podem estar desatualizados ou nem existir, não tem custo de
API/créditos mensais, e nunca escaneia IPs de terceiros sem relação com o
projeto — só o alvo que a equipe declarou.

Classificada como "Verificação Externa (Legal)" — reconhecimento leve,
não intrusivo (sem exploração, sem brute-force) — conforme decisão
registrada em CLAUDE.md.
"""

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

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

_WINDOWS_FALLBACK_PATH = r"C:\Program Files (x86)\Nmap\nmap.exe"


def _find_nmap() -> str | None:
    found = shutil.which("nmap")
    if found:
        return found
    if os.name == "nt" and os.path.exists(_WINDOWS_FALLBACK_PATH):
        return _WINDOWS_FALLBACK_PATH
    return None


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o host de {url}")
        return logs, findings

    nmap_binary = _find_nmap()
    if not nmap_binary:
        log("warning", "Nmap não encontrado nesta máquina — verificação de portas pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação de portas via Nmap não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'port_scan' precisa do binário 'nmap' disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo. Esta verificação simplesmente não rodou.",
                "recommendation": "Instalar o Nmap na máquina/container do worker (ex: `apt-get install nmap` no Linux, `winget install Insecure.Nmap` no Windows).",
                "reference_links": ["https://nmap.org/download.html"],
                "evidence": {"host": hostname},
            }
        )
        return logs, findings

    log("info", f"Rodando Nmap (TCP connect scan, top 100 portas) contra {hostname}")
    try:
        result = subprocess.run(
            [nmap_binary, "-Pn", "-sT", "-T4", "--top-ports", "100", "-oX", "-", hostname],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        log("error", "Nmap excedeu o tempo limite (120s).")
        return logs, findings
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao executar Nmap: {exc}")
        return logs, findings

    if result.returncode != 0:
        log("error", f"Nmap saiu com código {result.returncode}: {result.stderr[:300]}")
        return logs, findings

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        log("error", f"Falha ao interpretar saída XML do Nmap: {exc}")
        return logs, findings

    open_ports: list[dict] = []
    for port_el in root.findall(".//port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        port_num = int(port_el.get("portid"))
        proto = port_el.get("protocol")
        service_el = port_el.find("service")
        service_name = service_el.get("name") if service_el is not None else "desconhecido"
        product = service_el.get("product") if service_el is not None else None
        version = service_el.get("version") if service_el is not None else None
        banner = " ".join(filter(None, [product, version]))
        open_ports.append(
            {"port": port_num, "protocol": proto, "service": service_name, "banner": banner}
        )
        log("info", f"Porta {port_num}/{proto} aberta: {service_name} {banner}".rstrip())

    log("info", f"Nmap encontrou {len(open_ports)} porta(s) aberta(s) entre as 100 mais comuns")

    for p in open_ports:
        if p["port"] not in RISKY_PORTS:
            continue
        service_label = RISKY_PORTS[p["port"]]
        findings.append(
            {
                "severity": "alto",
                "title": f"Porta {p['port']} ({service_label}) exposta publicamente",
                "cwe": "CWE-200",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "description": (
                    f"Nmap encontrou a porta {p['port']}/{p['protocol']} aberta em {hostname}, "
                    f"rodando {p['service']}" + (f" ({p['banner']})" if p["banner"] else "") + "."
                ),
                "impact": f"Serviços como {service_label} não deveriam estar acessíveis diretamente pela internet — aumentam a superfície de ataque para brute-force, exploits conhecidos ou acesso não autorizado a dados.",
                "recommendation": f"Restringir o acesso à porta {p['port']} via firewall/security group (VPN ou IP allowlist), ou desativar o serviço se não for necessário publicamente.",
                "reference_links": [],
                "evidence": {"host": hostname, "port": p["port"], "service": p["service"], "banner": p["banner"]},
            }
        )

    findings.append(
        {
            "severity": "informativo",
            "title": f"{len(open_ports)} porta(s) aberta(s) encontradas via Nmap",
            "cwe": None,
            "owasp_category": None,
            "description": f"Lista completa de portas abertas em {hostname}: "
            + (", ".join(f"{p['port']}/{p['protocol']} ({p['service']})" for p in open_ports) or "nenhuma"),
            "impact": "Mapeamento de superfície de ataque.",
            "recommendation": "Revisar se todas as portas abertas são intencionais.",
            "reference_links": [],
            "evidence": {"host": hostname, "open_ports": open_ports},
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
