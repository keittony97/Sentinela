"""Varredura ATIVA de vulnerabilidades de infraestrutura via OpenVAS/Greenbone.

Ferramenta "vuln_scan_openvas": ATIVA — dispara um scan de verdade contra
o alvo através de um daemon GVM (gvmd) já provisionado (fora do escopo
deste worker: OpenVAS/Greenbone é uma stack própria, normalmente rodando
em containers separados com feed de vulnerabilidades sincronizado — ver
https://greenbone.github.io/docs/latest/). Este módulo só se conecta a um
gvmd já rodando via GMP (Greenbone Management Protocol, biblioteca
python-gvm); não sobe a stack sozinho.

Diferente da maioria das outras ferramentas, um scan OpenVAS completo
("Full and fast") costuma levar dezenas de minutos a horas. Para não
travar o worker (que processa um scan por vez), esta ferramenta cria e
inicia a task no GVM e aguarda só por um tempo limitado
(MAX_WAIT_SECONDS); se não terminar a tempo, registra um achado
informativo com o ID da task para acompanhamento manual no console do
GVM, em vez de bloquear indefinidamente.

Só disponível em projetos "Ambiente de Teste" autorizados (Nível 1 —
Detecção Ativa).
"""

import os
import time
from urllib.parse import urlparse

# Config padrão de scan "Full and fast" nos feeds default do Greenbone —
# UUID bem conhecido, estável entre instalações que usam o feed oficial.
DEFAULT_SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
# Target padrão de portas "All IANA assigned TCP" — também um UUID
# estável do feed oficial.
DEFAULT_PORT_LIST_ID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5"

POLL_INTERVAL_SECONDS = 15
MAX_WAIT_SECONDS = 300  # 5 min — scan completo pode levar muito mais; ver docstring.

OWASP_VULN_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"

SEVERITY_MAP = [
    (9.0, "critico"),
    (7.0, "alto"),
    (4.0, "medio"),
    (0.1, "baixo"),
]


def _cvss_to_severity(cvss: float) -> str:
    for threshold, sev in SEVERITY_MAP:
        if cvss >= threshold:
            return sev
    return "informativo"


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o host de {url}")
        return logs, findings

    username = os.environ.get("GVM_USERNAME")
    password = os.environ.get("GVM_PASSWORD")
    if not username or not password:
        log("warning", "GVM_USERNAME/GVM_PASSWORD não configurados — verificação via OpenVAS pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação via OpenVAS/Greenbone não executada (credenciais não configuradas)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'vuln_scan_openvas' precisa de um daemon GVM (gvmd) já provisionado e de GVM_USERNAME/GVM_PASSWORD configurados no ambiente do worker.",
                "impact": "Nenhum — apenas informativo. Esta é uma stack de infraestrutura própria (Docker Compose do Greenbone), não um binário simples.",
                "recommendation": "Provisionar o Greenbone Community Edition (https://greenbone.github.io/docs/latest/) e configurar GVM_SOCKET_PATH ou GVM_HOSTNAME/GVM_PORT + GVM_USERNAME/GVM_PASSWORD.",
                "reference_links": ["https://greenbone.github.io/docs/latest/"],
                "evidence": {"host": hostname},
            }
        )
        return logs, findings

    try:
        from gvm.connections import TLSConnection, UnixSocketConnection
        from gvm.protocols.gmp import Gmp
        from gvm.transforms import EtreeCheckCommandTransform
    except ImportError as exc:
        log("error", f"Biblioteca python-gvm não disponível: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação via OpenVAS/Greenbone não executada (biblioteca python-gvm ausente)",
                "cwe": None,
                "owasp_category": None,
                "description": "A dependência 'python-gvm' não está instalada no ambiente do worker.",
                "impact": "Nenhum — apenas informativo.",
                "recommendation": "Instalar 'python-gvm' (já listado em worker/requirements.txt).",
                "reference_links": ["https://greenbone.github.io/python-gvm/"],
                "evidence": {},
            }
        )
        return logs, findings

    socket_path = os.environ.get("GVM_SOCKET_PATH", "/run/gvmd/gvmd.sock")
    gvm_hostname = os.environ.get("GVM_HOSTNAME")
    gvm_port = int(os.environ.get("GVM_PORT", "9390"))

    try:
        connection = TLSConnection(hostname=gvm_hostname, port=gvm_port) if gvm_hostname else UnixSocketConnection(path=socket_path)
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao preparar conexão com o GVM: {exc}")
        return logs, findings

    try:
        with Gmp(connection=connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(username, password)
            log("info", f"Conectado ao GVM. Criando target para {hostname}")

            target_resp = gmp.create_target(
                name=f"sentinela-{hostname}-{int(time.time())}",
                hosts=[hostname],
                port_list_id=DEFAULT_PORT_LIST_ID,
            )
            target_id = target_resp.get("id")

            task_resp = gmp.create_task(
                name=f"sentinela-{hostname}-{int(time.time())}",
                config_id=DEFAULT_SCAN_CONFIG_ID,
                target_id=target_id,
                scanner_id=os.environ.get("GVM_SCANNER_ID", "08b69003-5fc2-4037-a479-93b440211c73"),
            )
            task_id = task_resp.get("id")

            gmp.start_task(task_id)
            log("info", f"Task GVM iniciada (id={task_id}). Aguardando até {MAX_WAIT_SECONDS}s pela conclusão.")

            waited = 0
            status = "Requested"
            while waited < MAX_WAIT_SECONDS:
                time.sleep(POLL_INTERVAL_SECONDS)
                waited += POLL_INTERVAL_SECONDS
                task = gmp.get_task(task_id)
                status_el = task.find(".//task/status")
                status = status_el.text if status_el is not None else status
                log("info", f"Task GVM {task_id}: status={status} ({waited}s decorridos)")
                if status in ("Done", "Stopped", "Interrupted"):
                    break

            if status != "Done":
                log("warning", f"Task GVM não terminou em {MAX_WAIT_SECONDS}s (status atual: {status}).")
                findings.append(
                    {
                        "severity": "informativo",
                        "title": "Scan OpenVAS iniciado, mas ainda em execução",
                        "cwe": None,
                        "owasp_category": None,
                        "description": f"A task GVM {task_id} contra {hostname} foi iniciada mas não terminou dentro do tempo de espera desta verificação ({MAX_WAIT_SECONDS}s). Status atual: {status}.",
                        "impact": "Scans completos de infraestrutura (OpenVAS) costumam levar dezenas de minutos a horas — isso é esperado, não uma falha.",
                        "recommendation": f"Acompanhar a conclusão diretamente no console do GVM (task id: {task_id}) e importar os achados manualmente quando terminar.",
                        "reference_links": [],
                        "evidence": {"task_id": task_id, "target_id": target_id, "status": status},
                    }
                )
                return logs, findings

            report_resp = gmp.get_task(task_id)
            report_id_el = report_resp.find(".//task/last_report/report")
            report_id = report_id_el.get("id") if report_id_el is not None else None
            if not report_id:
                log("error", "Task concluída mas não foi possível localizar o relatório.")
                return logs, findings

            report = gmp.get_report(report_id, details=True)
            results = report.findall(".//result")
            log("info", f"Scan OpenVAS concluído: {len(results)} resultado(s) no relatório.")

            for result in results:
                name_el = result.find("name")
                cvss_el = result.find("severity")
                nvt_el = result.find("nvt")
                desc_el = result.find("description")

                cvss = float(cvss_el.text) if cvss_el is not None and cvss_el.text else 0.0
                if cvss <= 0:
                    continue  # log-only entries, sem severidade real

                cve_el = nvt_el.find("cve") if nvt_el is not None else None
                cve = cve_el.text if cve_el is not None and cve_el.text and cve_el.text != "NOCVE" else None

                findings.append(
                    {
                        "severity": _cvss_to_severity(cvss),
                        "title": name_el.text if name_el is not None else "Vulnerabilidade detectada pelo OpenVAS",
                        "cwe": None,
                        "owasp_category": OWASP_VULN_COMPONENTS,
                        "description": (desc_el.text if desc_el is not None and desc_el.text else "")[:2000],
                        "impact": f"CVSS {cvss}" + (f" — {cve}" if cve else ""),
                        "recommendation": "Consultar o relatório completo no GVM para orientação de correção específica do NVT.",
                        "reference_links": [f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve else [],
                        "evidence": {"cvss": cvss, "cve": cve, "task_id": task_id, "report_id": report_id},
                    }
                )

    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha na comunicação com o GVM: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível completar a verificação via OpenVAS/Greenbone",
                "cwe": None,
                "owasp_category": None,
                "description": f"A comunicação com o daemon GVM falhou: {exc}",
                "impact": "Nenhum — apenas informativo. Verifique se o gvmd está acessível (socket/TLS) e as credenciais estão corretas.",
                "recommendation": "Confirmar que a stack do Greenbone está no ar e acessível a partir do worker.",
                "reference_links": ["https://greenbone.github.io/docs/latest/"],
                "evidence": {"host": hostname, "error": str(exc)},
            }
        )
        return logs, findings

    if not findings:
        findings.append(
            {
                "severity": "informativo",
                "title": "OpenVAS não encontrou vulnerabilidades com severidade atribuída",
                "cwe": None,
                "owasp_category": None,
                "description": f"O scan OpenVAS contra {hostname} terminou sem resultados com CVSS > 0.",
                "impact": "Nenhum indício encontrado nesta verificação.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"host": hostname},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
