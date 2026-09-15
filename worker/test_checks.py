import sys

sys.stdout.reconfigure(encoding="utf-8")

from checks import (
    amass_passive,
    cookie_security,
    cors_config,
    dns_records,
    exposed_files,
    hsts_mixed_content,
    js_secrets_scan,
    security_headers,
    storage_exposure,
    subdomains,
    tech_fingerprint,
    whois_lookup,
)

url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"

PASSIVE_CHECKS = [
    ("security_headers", security_headers),
    ("subdomains", subdomains),
    ("amass_passive", amass_passive),
    ("dns_records", dns_records),
    ("whois_lookup", whois_lookup),
    ("exposed_files", exposed_files),
    ("js_secrets_scan", js_secrets_scan),
    ("storage_exposure", storage_exposure),
    ("cookie_security", cookie_security),
    ("cors_config", cors_config),
    ("hsts_mixed_content", hsts_mixed_content),
    ("tech_fingerprint", tech_fingerprint),
]

for name, mod in PASSIVE_CHECKS:
    print(f"\n=== {name} ===")
    try:
        logs, findings = mod.run(url)
    except Exception as exc:  # noqa: BLE001
        print(f"  EXCEPTION: {exc!r}")
        continue
    for line in logs:
        print(f"  [{line['level']}] {line['message']}")
    print(f"  -> {len(findings)} finding(s)")
    for f in findings:
        print(f"     - [{f['severity']}] {f['title']}")
