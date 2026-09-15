FROM python:3.12-slim

WORKDIR /app

# nmap: usado pela ferramenta "port_scan" (checks/port_scan.py) para
# reconhecimento de portas/serviços — substitui a dependência de um
# serviço de terceiros (Shodan/Censys). git: só pra clonar o testssl.sh
# na sequência. bsdextrautils: traz o `hexdump` que o testssl.sh precisa
# (no Debian usado pela imagem python:3.12-slim, hexdump vem desse
# pacote, não do coreutils). sqlmap/hydra: pacotes apt oficiais do Debian,
# usados por checks/sqlmap_scan.py e checks/login_bruteforce.py
# (referência opcional — a implementação atual de login_bruteforce.py é
# 100% Python, não depende do binário hydra).
RUN apt-get update && apt-get install -y --no-install-recommends nmap git bsdextrautils sqlmap hydra \
    && rm -rf /var/lib/apt/lists/*

# Ferramentas ativas SEM pacote apt oficial — não instaladas aqui por não
# terem sido validadas em container (sem Docker nesta máquina de dev, ver
# CLAUDE.md). Cada checks/*.py correspondente já degrada graciosamente
# (achado informativo, não falha o scan) quando o binário não é
# encontrado — instalar sob demanda quando o worker for rodar de verdade:
#   - ffuf (content_discovery.py): https://github.com/ffuf/ffuf (binário Go)
#   - dalfox (xss_scan.py): https://github.com/hahwul/dalfox (binário Go)
#   - amass (amass_passive.py): https://github.com/owasp-amass/amass (binário Go)
#   - commix (command_injection_scan.py): `git clone https://github.com/commixproject/commix`
#   - wpscan (wpscan_check.py): `gem install wpscan` (exige Ruby)
#   - trivy (container_scan_trivy.py): https://aquasecurity.github.io/trivy/ (tem repo apt próprio)
#   - kube-hunter (kube_hunter_scan.py): `pip install kube-hunter`
#   - zap-api-scan.py (api_scan_zap.py): instalação completa do OWASP ZAP
#   - msfconsole (metasploit_confirm.py): https://github.com/rapid7/metasploit-framework
#   - Greenbone/GVM (vuln_scan_openvas.py): stack própria via Docker Compose, não um binário

# testssl.sh: usado pela ferramenta "tls_scan" (checks/tls_scan.py) para
# análise profunda de TLS (protocolos, cifras, vulnerabilidades
# conhecidas). Não tem pacote apt oficial — clonar é o caminho padrão.
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /app/vendor/testssl.sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
