"""Nível 2 — Exploração confirmatória via Metasploit Framework.

Ferramenta "metasploit_confirm": decisão de design deliberada, registrada
aqui e em CLAUDE.md — esta ferramenta NÃO seleciona nem dispara módulos
de exploit automaticamente contra o alvo. Fazer isso de forma autônoma
(sem um operador humano escolhendo o módulo/CVE específico e revisando o
payload) é um risco real e desnecessário de indisponibilizar o alvo ou
causar dano além do escopo confirmatório pretendido — exatamente o risco
que o próprio gate de "Exploração Confirmatória" (segunda confirmação +
justificativa, ver enforce_scan_legal_mode no banco) existe para
mitigar.

Em vez disso, esta ferramenta:
1. Confirma que o Metasploit Framework está disponível no worker (só
   como verificação de capacidade, não de exploração).
2. Registra um achado informativo orientando que a confirmação de
   exploração de uma vulnerabilidade específica (ex: um CVE já
   identificado por 'sqlmap_scan'/'vuln_scan_openvas' neste mesmo
   projeto) deve ser conduzida manualmente por um operador via
   msfconsole, escolhendo o módulo apropriado para aquele CVE.
3. A confirmação+justificativa desta ferramenta (exploitation_confirmed/
   exploitation_justification, gravadas no scan e no audit_log) servem
   para deixar rastreável QUEM autorizou e POR QUE a tentativa de
   confirmação manual aconteceu — não para autorizar um exploit
   automático disparado por este código.

Só disponível em projetos "Ambiente de Teste" autorizados, com a segunda
confirmação explícita de "Exploração Confirmatória" (Nível 2) marcada.
"""

import shutil
import subprocess

OWASP_VULN_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"


def _find_msfconsole() -> str | None:
    return shutil.which("msfconsole")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", "Ferramenta 'metasploit_confirm' (Nível 2 — Exploração Confirmatória) iniciada.")
    log(
        "warning",
        "Por design de segurança, esta ferramenta NÃO dispara exploits automaticamente — "
        "ver docstring de metasploit_confirm.py / CLAUDE.md para o racional.",
    )

    msfconsole = _find_msfconsole()
    if not msfconsole:
        log("warning", "msfconsole não encontrado nesta máquina.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Metasploit Framework não disponível neste worker",
                "cwe": None,
                "owasp_category": None,
                "description": "O binário 'msfconsole' não está disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo. A confirmação de exploração precisa ser conduzida manualmente por um operador com acesso ao Metasploit.",
                "recommendation": "Instalar o Metasploit Framework (https://github.com/rapid7/metasploit-framework) no ambiente onde a confirmação manual será conduzida — não precisa necessariamente ser neste worker.",
                "reference_links": ["https://github.com/rapid7/metasploit-framework"],
                "evidence": {"url": url},
            }
        )
        log("info", f"Verificação concluída: {len(findings)} achado(s).")
        return logs, findings

    log("info", "msfconsole encontrado — confirmando que o framework responde (sem executar exploits).")
    try:
        result = subprocess.run(
            [msfconsole, "-q", "-x", "version; exit"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        version_output = (result.stdout or "").strip()
        log("info", f"Metasploit disponível: {version_output[:200]}")
    except Exception as exc:  # noqa: BLE001
        log("error", f"msfconsole encontrado, mas falhou ao responder: {exc}")
        version_output = None

    findings.append(
        {
            "severity": "informativo",
            "title": "Exploração confirmatória (Nível 2) exige condução manual por um operador",
            "cwe": None,
            "owasp_category": OWASP_VULN_COMPONENTS,
            "description": (
                "Esta plataforma registrou a confirmação e a justificativa para tentar confirmar a "
                "exploração de uma vulnerabilidade já identificada neste projeto (ver audit_log, "
                "ação 'exploitation_tool_triggered'). Por segurança, nenhum módulo de exploit foi "
                "disparado automaticamente."
                + (f" Metasploit disponível no worker: {version_output[:200]}" if version_output else "")
            ),
            "impact": "Nenhum dano causado por esta execução — é uma verificação de capacidade e uma orientação de processo, não uma tentativa de exploração real.",
            "recommendation": (
                "Um operador humano deve revisar os achados deste projeto com CVE/vulnerabilidade "
                "confirmada (ex: de 'sqlmap_scan', 'vuln_scan_openvas'), escolher o módulo Metasploit "
                "apropriado para aquele CVE específico, e executar a confirmação manualmente via "
                "msfconsole, registrando o resultado como evidência manual no relatório."
            ),
            "reference_links": ["https://github.com/rapid7/metasploit-framework", "https://docs.metasploit.com/"],
            "evidence": {"url": url, "msfconsole_available": bool(version_output)},
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
