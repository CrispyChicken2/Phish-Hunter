# Browser that visits hostile pages. Kept separate from the rest of the project so
# the blast radius of a browser compromise is one throwaway container.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

WORKDIR /app

# Optional: trust a TLS-intercepting proxy or antivirus root CA. The directory is
# empty in a normal checkout, which makes this a no-op. pip pins its own CA bundle,
# so point it at the system store once the extra root is installed.
USER root
COPY docker/local-ca/ /usr/local/share/ca-certificates/
# update-ca-certificates only reads *.crt, so normalise whatever was dropped in.
RUN for f in /usr/local/share/ca-certificates/*.pem; do \
        [ -e "$f" ] && mv -- "$f" "${f%.pem}.crt"; \
    done; \
    update-ca-certificates
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt     SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Dependencies first: they change far less often than the source.
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# pwuser ships with the Playwright image; never run the browser as root.
USER pwuser

ENTRYPOINT ["lookalike-hunter"]
CMD ["capture"]
