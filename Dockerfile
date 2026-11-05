# Wraith Console — self-contained image.
# Playwright Python base (Chromium + OS deps preinstalled), the external scanning tools
# the console orchestrates, and the FastAPI web deps. Non-root runtime. Tools install
# tolerantly: one that fails to install reports "not installed" at runtime, it does not
# break the build.
FROM mcr.microsoft.com/playwright/python:v1.47.0-noble

# sqlmap (pure-Python) from source with a PATH wrapper.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --branch 1.10.10 --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# Recon: whatweb (apt); ffuf + katana (static Go release binaries).
RUN apt-get update && apt-get install -y --no-install-recommends unzip whatweb \
    && curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz -o /tmp/ffuf.tgz \
    && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf \
    && curl -fsSL https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip -o /tmp/katana.zip \
    && unzip -o /tmp/katana.zip -d /usr/local/bin katana \
    && chmod +x /usr/local/bin/ffuf /usr/local/bin/katana \
    && rm -f /tmp/ffuf.tgz /tmp/katana.zip && rm -rf /var/lib/apt/lists/*

# Scanners / fuzzers: nikto, hydra (apt); nuclei, dalfox, crlfuzz, kiterunner (release binaries).
RUN apt-get update && apt-get install -y --no-install-recommends nikto hydra git \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; t=$(mktemp -d); cd "$t"; \
    curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip -o n.zip && unzip -q n.zip; \
    curl -fsSL https://github.com/hahwul/dalfox/releases/download/v3.2.4/dalfox-v3.2.4-linux-x86_64.tar.gz -o d.tgz && tar xzf d.tgz; \
    curl -fsSL https://github.com/dwisiswant0/crlfuzz/releases/download/v1.4.1/crlfuzz_1.4.1_linux_amd64.tar.gz -o c.tgz && tar xzf c.tgz; \
    curl -fsSL https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz -o k.tgz && tar xzf k.tgz; \
    find . -type f -name nuclei   -exec install -m755 {} /usr/local/bin/nuclei \; ; \
    find . -type f -name dalfox   -exec install -m755 {} /usr/local/bin/dalfox \; ; \
    find . -type f -name crlfuzz  -exec install -m755 {} /usr/local/bin/crlfuzz \; ; \
    find . -type f \( -name kr -o -name kiterunner \) -exec install -m755 {} /usr/local/bin/kr \; ; \
    cd /; rm -rf "$t"; \
    for b in nuclei dalfox crlfuzz kr; do test -x /usr/local/bin/$b || { echo "MISSING $b"; exit 1; }; done
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates \
    && chmod -R a+rX /opt/nuclei-templates
RUN for r in commixproject/commix vladko312/SSTImap s0md3v/Corsy r0075h3ll/Oralyzer \
             ticarpi/jwt_tool drwetter/testssl.sh dolevf/graphw00f defparam/smuggler \
             GerbenJavado/LinkFinder m4ll0k/SecretFinder Tuhinshubhra/CMSeeK; do \
      git clone --depth 1 "https://github.com/$r" "/opt/$(basename $r)" || echo "clone failed: $r"; \
    done \
    && for d in /opt/commix /opt/SSTImap /opt/Corsy /opt/Oralyzer /opt/jwt_tool /opt/graphw00f \
                /opt/smuggler /opt/LinkFinder /opt/SecretFinder /opt/CMSeeK; do \
      [ -f "$d/requirements.txt" ] && pip install --no-cache-dir -r "$d/requirements.txt" || true; \
    done \
    && chmod -R a+rX /opt && chmod +x /opt/testssl.sh/testssl.sh 2>/dev/null; true
RUN pip install --no-cache-dir /opt/Oralyzer || echo "WARN: oralyzer install failed"

# feroxbuster (Rust release binary), XSStrike (clone), wpscan (Ruby gem; tolerant).
RUN curl -fsSL https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86_64-linux-feroxbuster.tar.gz -o /tmp/ferox.tgz \
    && tar -xzf /tmp/ferox.tgz -C /usr/local/bin feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster && rm -f /tmp/ferox.tgz \
    && test -x /usr/local/bin/feroxbuster
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/XSStrike \
    && (pip install --no-cache-dir -r /opt/XSStrike/requirements.txt || echo "WARN: xsstrike deps failed") \
    && chmod -R a+rX /opt/XSStrike
RUN apt-get update \
    && apt-get install -y --no-install-recommends ruby ruby-dev build-essential libcurl4-openssl-dev zlib1g-dev \
    && (gem install wpscan -v 3.8.28 --no-document \
        && ln -sf "$(ruby -e 'puts Gem.bindir')/wpscan" /usr/local/bin/wpscan \
        || echo "WARN: wpscan gem install failed") \
    && rm -rf /var/lib/apt/lists/*

# nosqli, gobuster, ppfuzz (release binaries); joomscan (Perl clone), droopescan (pip); SecLists wordlists.
RUN (curl -fsSL https://github.com/Charlie-belmer/nosqli/releases/download/v0.5.4/nosqli_linux_x64_v0.5.4 -o /usr/local/bin/nosqli \
       && chmod +x /usr/local/bin/nosqli && echo "nosqli OK") || echo "WARN nosqli install failed"; \
    (curl -fsSL https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz -o /tmp/gob.tgz \
       && tar -xzf /tmp/gob.tgz -C /usr/local/bin gobuster && chmod +x /usr/local/bin/gobuster && rm -f /tmp/gob.tgz && echo "gobuster OK") || echo "WARN gobuster install failed"; \
    (curl -fsSL https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.2/ppfuzz-v1.0.2-x86_64-unknown-linux-musl.tar.gz -o /tmp/pp.tgz \
       && tar -xzf /tmp/pp.tgz -C /tmp && find /tmp -type f -name ppfuzz -exec install -m755 {} /usr/local/bin/ppfuzz \; && rm -f /tmp/pp.tgz && echo "ppfuzz OK") || echo "WARN ppfuzz install failed"; true
RUN git clone --depth 1 https://github.com/OWASP/joomscan /opt/joomscan \
    && apt-get update && apt-get install -y --no-install-recommends libwww-perl \
    && rm -rf /var/lib/apt/lists/* && chmod -R a+rX /opt/joomscan
RUN pip install --no-cache-dir droopescan || echo "WARN: droopescan install failed"
RUN mkdir -p /opt/wordlists \
    && curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -o /opt/wordlists/content.txt \
    && curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -o /opt/wordlists/vhosts.txt \
    && chmod -R a+rX /opt/wordlists

WORKDIR /app
COPY requirements-ui.txt .
RUN pip install --no-cache-dir -r requirements-ui.txt
RUN pip install --no-cache-dir wafw00f==2.3.1 arjun==2.2.7
RUN pip install --no-cache-dir wapiti3 || echo "WARN: wapiti3 install failed"
RUN pip install --no-cache-dir clairvoyance || echo "WARN: clairvoyance install failed"

# patched Chromium (CDP leak fix); tolerant — falls back to stock Playwright if it fails.
RUN (pip install --no-cache-dir patchright && patchright install chromium \
     && chmod -R a+rX /ms-playwright) \
    || echo "WARN: patchright unavailable — browser falls back to stock Playwright"

COPY mcp_server/ ./mcp_server/
COPY ui/ ./ui/
COPY scope.yaml ./scope.yaml

RUN mkdir -p /app/evidence /app/private && useradd -m -u 10001 pentest && chown -R pentest:pentest /app
USER pentest

ENV PENTEST_SCOPE_FILE=/app/scope.yaml \
    PENTEST_EVIDENCE_DIR=/app/evidence \
    PYTHONPATH=/app \
    DO_NOT_TRACK=1

EXPOSE 8000
CMD ["uvicorn", "ui.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
