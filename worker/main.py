import asyncio
import os
import traceback
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI  # noqa: E402

import db  # noqa: E402
from checks import (  # noqa: E402
    amass_passive,
    api_scan_zap,
    basic_injection_probe,
    command_injection_scan,
    container_scan_trivy,
    content_discovery,
    cookie_security,
    cors_config,
    dns_records,
    exposed_files,
    graphql_scan,
    hibp_check,
    hsts_mixed_content,
    js_secrets_scan,
    kube_hunter_scan,
    login_bruteforce,
    metasploit_confirm,
    port_scan,
    security_headers,
    sqlmap_scan,
    storage_exposure,
    subdomains,
    tech_fingerprint,
    tls_scan,
    vuln_scan_openvas,
    whois_lookup,
    wpscan_check,
    xss_scan,
)

POLL_INTERVAL_SECONDS = float(os.environ.get("POLL_INTERVAL_SECONDS", "3"))

# Ferramentas ativas Nível 1 (Detecção Ativa): is_active_tool=false, disponíveis em qualquer
# modalidade legal. Ferramentas ativas (ver ACTIVE_TOOL_IDS): só rodam em
# scans com is_active_tool=true, o que o banco (enforce_scan_legal_mode)
# só aceita em projeto "ambiente_teste" autorizado E disparado por Admin
# — reforçado aqui de novo por defesa em profundidade, não só confiar na
# UI/banco terem feito a checagem antes de chegar no worker.
ACTIVE_TOOL_IDS = {
    "basic_injection_probe",
    "port_scan",
    "content_discovery",
    "sqlmap_scan",
    "xss_scan",
    "command_injection_scan",
    "wpscan_check",
    "login_bruteforce",
    "vuln_scan_openvas",
    "api_scan_zap",
    "graphql_scan",
    "container_scan_trivy",
    "kube_hunter_scan",
}

# Ferramentas ativas Nível 2 (Exploração Confirmatória): além de
# is_active_tool=true, exigem is_exploitation_tool=true no scan — o banco
# (enforce_scan_legal_mode) só aceita isso com exploitation_confirmed=true
# e exploitation_justification preenchida, separados da autorização geral
# do projeto. Reforçado aqui de novo por defesa em profundidade.
EXPLOITATION_TOOL_IDS = {"metasploit_confirm"}

TOOL_RUNNERS = {
    "headers_tls": security_headers.run,
    "tls_scan": tls_scan.run,
    "subdomains": subdomains.run,
    "exposed_files": exposed_files.run,
    "port_scan": port_scan.run,
    "basic_injection_probe": basic_injection_probe.run,
    "storage_exposure": storage_exposure.run,
    # Verificação Externa (passivas) — adicionadas para cobrir DNS/WHOIS/
    # Amass passivo, cookies/CORS/HSTS/mixed content, fingerprint, segredos
    # em JS público e Have I Been Pwned (ver CLAUDE.md).
    "dns_records": dns_records.run,
    "whois_lookup": whois_lookup.run,
    "amass_passive": amass_passive.run,
    "cookie_security": cookie_security.run,
    "cors_config": cors_config.run,
    "hsts_mixed_content": hsts_mixed_content.run,
    "tech_fingerprint": tech_fingerprint.run,
    "js_secrets_scan": js_secrets_scan.run,
    "hibp_check": hibp_check.run,
    # Ambiente de Teste — Nível 1 (Detecção Ativa).
    "content_discovery": content_discovery.run,
    "sqlmap_scan": sqlmap_scan.run,
    "xss_scan": xss_scan.run,
    "command_injection_scan": command_injection_scan.run,
    "wpscan_check": wpscan_check.run,
    "login_bruteforce": login_bruteforce.run,
    "vuln_scan_openvas": vuln_scan_openvas.run,
    "api_scan_zap": api_scan_zap.run,
    "graphql_scan": graphql_scan.run,
    "container_scan_trivy": container_scan_trivy.run,
    "kube_hunter_scan": kube_hunter_scan.run,
    # Ambiente de Teste — Nível 2 (Exploração Confirmatória).
    "metasploit_confirm": metasploit_confirm.run,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def process_next_scan() -> bool:
    """Reivindica e processa um scan da fila. Retorna True se algo foi processado."""
    queued = db.select(
        "scans",
        {"status": "eq.na_fila", "order": "created_at.asc", "limit": "1"},
    )
    if not queued:
        return False

    scan_id = queued[0]["id"]

    # Claim atômico: só continua se ainda estava "na_fila" (evita corrida
    # entre múltiplas instâncias do worker pegando o mesmo scan).
    claimed = db.update(
        "scans",
        {"id": f"eq.{scan_id}", "status": "eq.na_fila"},
        {"status": "em_execucao", "started_at": _now_iso()},
    )
    if not claimed:
        return False

    scan = claimed[0]
    org_id = scan["organization_id"]
    project_id = scan["project_id"]
    tools = scan.get("tools_used") or []
    is_active_scan = bool(scan.get("is_active_tool"))
    is_exploitation_scan = bool(scan.get("is_exploitation_tool"))

    def log(tool: str, level: str, message: str) -> None:
        print(f"[scan {scan_id}] [{level}] [{tool}] {message}")
        db.insert(
            "scan_logs",
            {"organization_id": org_id, "scan_id": scan_id, "tool": tool, "level": level, "message": message},
        )

    project = db.select("projects", {"id": f"eq.{project_id}", "select": "target_id"})
    target = db.select("targets", {"id": f"eq.{project[0]['target_id']}", "select": "url"})
    target_url = target[0]["url"]

    status = "concluido"
    all_findings: list[dict] = []

    try:
        for tool in tools:
            runner = TOOL_RUNNERS.get(tool)
            if runner is None:
                log(tool, "warning", f"Ferramenta desconhecida ou ainda não implementada: {tool}")
                continue

            # Defesa em profundidade: o gate de verdade é o trigger no banco
            # (enforce_scan_legal_mode), mas o worker confere de novo antes
            # de rodar qualquer ferramenta ativa — nunca confiar cegamente
            # em dado que chegou até aqui.
            if tool in ACTIVE_TOOL_IDS and not is_active_scan:
                log(tool, "error", f"Ferramenta ativa '{tool}' bloqueada: scan não está marcado como is_active_tool")
                continue

            if tool in EXPLOITATION_TOOL_IDS and not is_exploitation_scan:
                log(tool, "error", f"Ferramenta de exploração confirmatória '{tool}' bloqueada: scan não está marcado como is_exploitation_tool")
                continue

            log(tool, "info", f"Ferramenta '{tool}' iniciada para {target_url}")
            lines, findings = runner(target_url)
            for line in lines:
                log(tool, line["level"], line["message"])
            all_findings.extend(findings)
    except Exception:  # noqa: BLE001
        status = "falhou"
        log("worker", "error", f"Scan falhou com exceção:\n{traceback.format_exc()}")

    for finding in all_findings:
        db.insert("findings", {"organization_id": org_id, "scan_id": scan_id, **finding})

    db.update("scans", {"id": f"eq.{scan_id}"}, {"status": status, "finished_at": _now_iso()})
    log("worker", "info", f"Scan finalizado com status '{status}'.")
    return True


async def poll_loop() -> None:
    print(f"[worker] iniciando polling a cada {POLL_INTERVAL_SECONDS}s")
    while True:
        try:
            processed = await asyncio.to_thread(process_next_scan)
        except Exception:  # noqa: BLE001
            print(f"[worker] erro no loop de polling:\n{traceback.format_exc()}")
            processed = False
        await asyncio.sleep(0.5 if processed else POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(poll_loop())
    yield
    task.cancel()


app = FastAPI(title="Sentinela Worker", lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
