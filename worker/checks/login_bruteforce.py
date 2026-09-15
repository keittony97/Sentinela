"""Brute-force CONTROLADO de credenciais fracas/padrão em formulário de login.

Ferramenta "login_bruteforce": ATIVA — testa um número BEM pequeno de
combinações usuário/senha comuns/padrão (não uma wordlist extensa) contra
o formulário de login detectado na página, com um atraso fixo entre
tentativas (RATE_LIMIT_SECONDS) para reduzir o risco de lockout de contas
mesmo em ambiente de teste autorizado. Implementado em Python puro (sem
depender do binário Hydra/ffuf) para ficar autocontido — a ideia é a
mesma que Hydra/ffuf fariam contra um form HTTP: descobrir o form, testar
poucas credenciais, comparar a resposta com uma tentativa deliberadamente
errada. Só disponível em projetos "Ambiente de Teste" autorizados
(Nível 1 — Detecção Ativa).
"""

import re
import time
from urllib.parse import urljoin

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_AUTH = "A07:2021 - Identification and Authentication Failures"

RATE_LIMIT_SECONDS = 2.0

# Combinações deliberadamente poucas — o objetivo é detectar credenciais
# padrão/óbvias esquecidas, não fazer um ataque de força bruta de verdade.
CREDENTIAL_CANDIDATES = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "123456"),
    ("test", "test123"),
]

FORM_PATTERN = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ACTION_PATTERN = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
METHOD_PATTERN = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
INPUT_PATTERN = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
NAME_PATTERN = re.compile(r'name=["\']([^"\']*)["\']', re.IGNORECASE)
TYPE_PATTERN = re.compile(r'type=["\']([^"\']*)["\']', re.IGNORECASE)


def _find_login_form(html: str, base_url: str):
    for form_match in FORM_PATTERN.finditer(html):
        form_html = form_match.group(0)
        inputs = form_html
        has_password = False
        username_field = None
        password_field = None

        for input_match in INPUT_PATTERN.finditer(inputs):
            attrs = input_match.group(1)
            type_match = TYPE_PATTERN.search(attrs)
            name_match = NAME_PATTERN.search(attrs)
            input_type = (type_match.group(1).lower() if type_match else "text")
            name = name_match.group(1) if name_match else None

            if input_type == "password" and name:
                has_password = True
                password_field = name
            elif input_type in ("text", "email") and name and username_field is None:
                if any(k in name.lower() for k in ("user", "email", "login", "usuario")):
                    username_field = name
                elif username_field is None:
                    username_field = name

        if has_password and username_field and password_field:
            action_match = ACTION_PATTERN.search(form_match.group(0))
            method_match = METHOD_PATTERN.search(form_match.group(0))
            action = action_match.group(1) if action_match else ""
            method = (method_match.group(1).upper() if method_match else "POST")
            return {
                "action_url": urljoin(base_url, action) if action else base_url,
                "method": method,
                "username_field": username_field,
                "password_field": password_field,
            }
    return None


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", f"Procurando formulário de login em {url}")
    try:
        resp = httpx.get(url, follow_redirects=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao conectar: {exc}")
        return logs, findings

    form = _find_login_form(resp.text, str(resp.url))
    if not form:
        log("info", "Nenhum formulário de login (campo de senha) encontrado na página — nada para testar.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum formulário de login detectado",
                "cwe": None,
                "owasp_category": None,
                "description": f"A página {url} não tem um <form> com campo de senha detectável.",
                "impact": "Nenhum — esta ferramenta só testa formulários de login na própria URL fornecida.",
                "recommendation": "Se o login estiver em outra URL, rodar esta verificação apontando diretamente para a página de login.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log(
        "info",
        f"Formulário de login encontrado: action={form['action_url']} method={form['method']} "
        f"campos=({form['username_field']}, {form['password_field']})",
    )
    log("info", f"Testando {len(CREDENTIAL_CANDIDATES)} combinação(ões) padrão, com {RATE_LIMIT_SECONDS}s entre tentativas")

    # Baseline: uma credencial certamente errada, pra comparar a resposta.
    baseline_data = {
        form["username_field"]: "sentinela_baseline_nao_existe",
        form["password_field"]: "sentinela_baseline_nao_existe",
    }
    try:
        submit = httpx.post if form["method"] == "POST" else httpx.get
        baseline_resp = submit(
            form["action_url"], data=baseline_data if form["method"] == "POST" else None,
            params=baseline_data if form["method"] != "POST" else None,
            follow_redirects=True, timeout=15,
        )
        baseline_signature = (baseline_resp.status_code, len(baseline_resp.content))
        log("info", f"Baseline (credencial inexistente): HTTP {baseline_resp.status_code}, {len(baseline_resp.content)} bytes")
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao obter baseline: {exc}")
        return logs, findings

    time.sleep(RATE_LIMIT_SECONDS)

    successful = []
    for username, password in CREDENTIAL_CANDIDATES:
        data = {form["username_field"]: username, form["password_field"]: password}
        try:
            submit = httpx.post if form["method"] == "POST" else httpx.get
            attempt_resp = submit(
                form["action_url"], data=data if form["method"] == "POST" else None,
                params=data if form["method"] != "POST" else None,
                follow_redirects=True, timeout=15,
            )
            signature = (attempt_resp.status_code, len(attempt_resp.content))
            differs = signature != baseline_signature
            log(
                "info" if not differs else "warning",
                f"'{username}'/'{password}': HTTP {attempt_resp.status_code}, {len(attempt_resp.content)} bytes"
                + (" — DIFERE do baseline (possível sucesso)" if differs else " — igual ao baseline"),
            )
            if differs:
                successful.append({"username": username, "password": password, "status_code": attempt_resp.status_code})
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao testar '{username}'/'{password}': {exc}")

        time.sleep(RATE_LIMIT_SECONDS)

    if successful:
        findings.append(
            {
                "severity": "critico",
                "title": "Possível login com credencial padrão/fraca aceito",
                "cwe": "CWE-521",
                "owasp_category": OWASP_AUTH,
                "description": "As seguintes combinações produziram uma resposta diferente da tentativa com credencial deliberadamente inexistente, sugerindo autenticação bem-sucedida: "
                + ", ".join(f"{s['username']}/{s['password']}" for s in successful)
                + ". IMPORTANTE: comparação heurística baseada em status/tamanho de resposta — confirmar manualmente antes de agir.",
                "impact": "Credenciais padrão/óbvias permitem acesso não autorizado imediato à aplicação, possivelmente com privilégios administrativos.",
                "recommendation": "Trocar imediatamente qualquer credencial padrão/fraca encontrada, forçar política de senha forte e habilitar MFA/bloqueio por tentativas.",
                "reference_links": ["https://owasp.org/www-community/attacks/Brute_force_attack"],
                "evidence": {"url": form["action_url"], "candidates_matched": successful},
            }
        )
    else:
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhuma credencial padrão/fraca testada foi aceita",
                "cwe": None,
                "owasp_category": None,
                "description": f"Testadas {len(CREDENTIAL_CANDIDATES)} combinação(ões) comum(ns) contra {form['action_url']} sem indício de sucesso.",
                "impact": "Nenhum indício encontrado — esta verificação testa só um conjunto bem pequeno de credenciais óbvias, não substitui uma política de senha forte.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"url": form["action_url"], "candidates_tested": len(CREDENTIAL_CANDIDATES)},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
