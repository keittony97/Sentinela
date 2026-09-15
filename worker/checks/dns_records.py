"""Verificação passiva de registros DNS (SPF, DKIM, DMARC, DNSSEC, MX).

Ferramenta "dns_records": só faz consultas DNS padrão (o mesmo que
qualquer resolvedor faz) — nunca toca o alvo diretamente. Disponível em
qualquer modalidade legal.
"""

from urllib.parse import urlparse

import dns.resolver

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"

# Seletores DKIM comuns — sem acesso ao painel de e-mail do domínio não dá
# pra saber o seletor real, então testamos os mais usados na prática
# (Google Workspace, Microsoft 365, Mailchimp, SendGrid, provedores
# genéricos). Achar nenhum não prova ausência de DKIM, só que nenhum
# seletor comum está publicado.
COMMON_DKIM_SELECTORS = [
    "google",
    "default",
    "selector1",
    "selector2",
    "k1",
    "mail",
    "dkim",
    "smtp",
]


def _apex_domain(hostname: str) -> str:
    labels = hostname.lower().split(".")
    two_level_tlds = {"com.br", "net.br", "org.br", "gov.br", "co.uk", "org.uk", "com.au", "co.jp"}
    if len(labels) <= 2:
        return hostname.lower()
    last_two = ".".join(labels[-2:])
    if last_two in two_level_tlds and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _resolve(resolver: dns.resolver.Resolver, name: str, rdtype: str):
    try:
        return [r.to_text() for r in resolver.resolve(name, rdtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except Exception:  # noqa: BLE001
        return []


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o domínio de {url}")
        return logs, findings

    domain = _apex_domain(hostname)
    log("info", f"Consultando registros DNS de {domain} (MX, SPF, DMARC, DKIM, DNSSEC)")

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    # --- MX ---
    mx_records = _resolve(resolver, domain, "MX")
    if mx_records:
        log("info", f"MX: {', '.join(mx_records)}")
    else:
        log("info", "Nenhum registro MX encontrado — domínio provavelmente não recebe e-mail direto.")

    # --- SPF (registro TXT começando com v=spf1) ---
    txt_records = _resolve(resolver, domain, "TXT")
    spf_records = [t for t in txt_records if "v=spf1" in t.lower()]
    if not spf_records:
        log("warning", "Nenhum registro SPF encontrado.")
        findings.append(
            {
                "severity": "medio",
                "title": "Registro SPF ausente",
                "cwe": "CWE-290",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"O domínio {domain} não tem um registro TXT SPF (v=spf1) publicado.",
                "impact": "Sem SPF, qualquer servidor pode enviar e-mail forjando o domínio do remetente — facilita phishing/spoofing usando o nome da organização.",
                "recommendation": "Publicar um registro SPF (TXT) listando os servidores autorizados a enviar e-mail em nome do domínio, terminando em '-all' ou '~all'.",
                "reference_links": ["https://datatracker.ietf.org/doc/html/rfc7208"],
                "evidence": {"domain": domain, "txt_records": txt_records},
            }
        )
    else:
        log("info", f"SPF encontrado: {spf_records[0][:150]}")
        if "+all" in spf_records[0].lower():
            findings.append(
                {
                    "severity": "alto",
                    "title": "Registro SPF permissivo demais (+all)",
                    "cwe": "CWE-290",
                    "owasp_category": OWASP_MISCONFIG,
                    "description": f"O SPF de {domain} termina em '+all', que autoriza QUALQUER servidor a enviar e-mail em nome do domínio.",
                    "impact": "Anula completamente a proteção do SPF contra spoofing de e-mail.",
                    "recommendation": "Trocar '+all' por '-all' (fail) ou, no mínimo, '~all' (softfail), e listar explicitamente os servidores autorizados.",
                    "reference_links": ["https://datatracker.ietf.org/doc/html/rfc7208"],
                    "evidence": {"domain": domain, "spf": spf_records[0]},
                }
            )

    # --- DMARC (TXT em _dmarc.<domínio>) ---
    dmarc_records = _resolve(resolver, f"_dmarc.{domain}", "TXT")
    dmarc_records = [t for t in dmarc_records if "v=dmarc1" in t.lower()]
    if not dmarc_records:
        log("warning", "Nenhum registro DMARC encontrado.")
        findings.append(
            {
                "severity": "medio",
                "title": "Registro DMARC ausente",
                "cwe": "CWE-290",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"O domínio {domain} não tem um registro DMARC (_dmarc.{domain}) publicado.",
                "impact": "Sem DMARC, não há política declarada de como tratar e-mails que falham SPF/DKIM, nem relatórios de tentativas de spoofing usando o domínio.",
                "recommendation": "Publicar um registro DMARC (TXT em _dmarc.<domínio>), começando com 'p=none' para monitorar e evoluindo para 'p=quarantine'/'p=reject'.",
                "reference_links": ["https://datatracker.ietf.org/doc/html/rfc7489"],
                "evidence": {"domain": domain},
            }
        )
    else:
        log("info", f"DMARC encontrado: {dmarc_records[0][:150]}")
        if "p=none" in dmarc_records[0].lower():
            findings.append(
                {
                    "severity": "baixo",
                    "title": "Política DMARC em modo monitoramento (p=none)",
                    "cwe": "CWE-290",
                    "owasp_category": OWASP_MISCONFIG,
                    "description": f"O DMARC de {domain} está com 'p=none' — só monitora, não bloqueia e-mails forjados.",
                    "impact": "E-mails que falham SPF/DKIM continuam sendo entregues normalmente, mesmo parecendo vir do domínio da organização.",
                    "recommendation": "Evoluir a política para 'p=quarantine' e depois 'p=reject' após validar que os relatórios (rua=) não mostram falsos positivos.",
                    "reference_links": ["https://datatracker.ietf.org/doc/html/rfc7489"],
                    "evidence": {"domain": domain, "dmarc": dmarc_records[0]},
                }
            )

    # --- DKIM (seletores comuns) ---
    found_selectors = []
    for selector in COMMON_DKIM_SELECTORS:
        records = _resolve(resolver, f"{selector}._domainkey.{domain}", "TXT")
        if records:
            found_selectors.append(selector)
    if found_selectors:
        log("info", f"DKIM encontrado nos seletores comuns: {', '.join(found_selectors)}")
    else:
        log("info", "Nenhum seletor DKIM comum encontrado (não prova ausência — seletor pode ser customizado).")
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum registro DKIM encontrado nos seletores comuns testados",
                "cwe": None,
                "owasp_category": None,
                "description": f"Testados os seletores comuns ({', '.join(COMMON_DKIM_SELECTORS)}) em _domainkey.{domain}, nenhum retornou registro.",
                "impact": "Sem DKIM, não há assinatura criptográfica confirmando que o e-mail não foi alterado em trânsito — mas o seletor real pode ser outro, não usado no teste.",
                "recommendation": "Confirmar manualmente com o time de e-mail/DNS qual seletor DKIM está em uso, e garantir que esteja publicado e configurado corretamente.",
                "reference_links": ["https://datatracker.ietf.org/doc/html/rfc6376"],
                "evidence": {"domain": domain, "selectors_tested": COMMON_DKIM_SELECTORS},
            }
        )

    # --- DNSSEC (existência de DNSKEY na zona) ---
    dnskey_records = _resolve(resolver, domain, "DNSKEY")
    if dnskey_records:
        log("info", f"DNSSEC ativo — {len(dnskey_records)} DNSKEY encontrada(s).")
    else:
        log("info", "DNSSEC não detectado (sem DNSKEY na zona).")
        findings.append(
            {
                "severity": "baixo",
                "title": "DNSSEC não habilitado",
                "cwe": "CWE-345",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"Não foi encontrado registro DNSKEY para {domain} — a zona provavelmente não usa DNSSEC.",
                "impact": "Sem DNSSEC, respostas DNS não são assinadas criptograficamente, facilitando ataques de cache poisoning/spoofing DNS.",
                "recommendation": "Habilitar DNSSEC no provedor de DNS do domínio, se disponível.",
                "reference_links": ["https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"],
                "evidence": {"domain": domain},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
