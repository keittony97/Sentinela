import sys

sys.stdout.reconfigure(encoding="utf-8")

from checks import exposed_files, exposed_ports, storage_exposure, subdomains

url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"

for name, mod in [
    ("subdomains", subdomains),
    ("exposed_files", exposed_files),
    ("exposed_ports", exposed_ports),
    ("storage_exposure", storage_exposure),
]:
    print(f"\n=== {name} ===")
    logs, findings = mod.run(url)
    for line in logs:
        print(f"  [{line['level']}] {line['message']}")
    print(f"  -> {len(findings)} finding(s)")
    for f in findings:
        print(f"     - [{f['severity']}] {f['title']}")
