# Browser that visits hostile pages. Kept separate from the rest of the project so
# the blast radius of a browser compromise is one throwaway container.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

# Pinned: the image must build the same way tomorrow as today.
COPY --from=ghcr.io/astral-sh/uv:0.11.21 /uv /usr/local/bin/uv

ENV PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    HOME=/tmp \
    PATH=/app/.venv/bin:$PATH

WORKDIR /app

# Optional: trust a TLS-intercepting proxy or antivirus root CA. The directory is
# empty in a normal checkout, which makes this a no-op.
COPY docker/local-ca/ /usr/local/share/ca-certificates/
# update-ca-certificates only reads *.crt, so normalise whatever was dropped in.
RUN for f in /usr/local/share/ca-certificates/*.pem; do \
        [ -e "$f" ] && mv -- "$f" "${f%.pem}.crt"; \
    done; \
    update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    UV_NATIVE_TLS=true

# Install from the lockfile: exact versions, same as CI and the developer machine.
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv sync --locked --no-dev

# pwuser ships with the Playwright image; never run the browser as root.
USER pwuser

ENTRYPOINT ["lookalike-hunter"]
CMD ["capture"]
