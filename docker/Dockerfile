FROM golang:1.27.1-alpine AS cicada-builder

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY

ENV http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    all_proxy=${ALL_PROXY} \
    no_proxy=${NO_PROXY}

RUN apk add --no-cache python3 gzip

WORKDIR /src
COPY cicada-go/go.mod cicada-go/go.sum ./
RUN go mod download
COPY cicada-go/ ./
COPY scripts/write-web-panel-manifest.py /tmp/write-web-panel-manifest.py
RUN mkdir -p /src/internal/server/ui/generated \
    && GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath \
       -o /tmp/cicada-webcrypto.wasm ./cmd/cicada-webcrypto \
    && runtime="$(go env GOROOT)/lib/wasm/wasm_exec.js" \
    && if [ ! -f "$runtime" ]; then runtime="$(go env GOROOT)/misc/wasm/wasm_exec.js"; fi \
    && cp "$runtime" /src/internal/server/ui/generated/wasm_exec.js \
    && gzip -n -9 -c /tmp/cicada-webcrypto.wasm > /src/internal/server/ui/generated/cicada-webcrypto.wasm.gz \
    && python3 /tmp/write-web-panel-manifest.py /src/internal/server/ui/generated "$(go version)" /tmp/cicada-webcrypto.wasm \
    && rm -f /tmp/cicada-webcrypto.wasm
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/cicada ./cmd/cicada

FROM ubuntu:26.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TZ=Etc/UTC
ARG CICADA_UID=1000
ARG CICADA_GID=1000
ARG CODEX_RELEASE=0.159.2
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=${TZ} \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/home/cicada \
    CODEX_HOME=/home/cicada/.codex \
    PATH=/home/cicada/.local/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        jq \
        openssh-client \
        procps \
        python3 \
        python3-venv \
        tmux \
        tzdata \
    && existing_group="$(getent group "${CICADA_GID}" | cut -d: -f1 || true)" \
    && if [ -n "$existing_group" ]; then \
         [ "$existing_group" = cicada ] || groupmod --new-name cicada "$existing_group"; \
       else \
         groupadd --gid "${CICADA_GID}" cicada; \
       fi \
    && existing_user="$(getent passwd "${CICADA_UID}" | cut -d: -f1 || true)" \
    && if [ -n "$existing_user" ]; then \
         usermod --login cicada --home /home/cicada --move-home "$existing_user"; \
       else \
         useradd --create-home --shell /bin/bash \
           --uid "${CICADA_UID}" --gid "${CICADA_GID}" cicada; \
       fi \
    && usermod --gid "${CICADA_GID}" cicada \
    && install --directory --owner=cicada --group=cicada \
        /home/cicada/.codex \
        /workspace \
        /var/log/cicada/codex \
    && rm -rf /var/lib/apt/lists/*

# Install the official Codex CLI standalone binary. The installer is run at
# image-build time; credentials are supplied only at container runtime.
RUN export http_proxy="${HTTP_PROXY:-}" https_proxy="${HTTPS_PROXY:-}" \
    all_proxy="${ALL_PROXY:-}" no_proxy="${NO_PROXY:-}" \
    && curl -fsSL https://chatgpt.com/codex/install.sh \
       | CODEX_NON_INTERACTIVE=1 \
         CODEX_INSTALL_DIR=/usr/local/bin \
         CODEX_HOME=/opt/codex \
         sh -s -- --release "${CODEX_RELEASE}" \
    && test "$(codex --version)" = "codex-cli ${CODEX_RELEASE}"

# The standalone package also ships the code-mode helper. The installer cannot
# create this alias when CODEX_HOME differs from the runtime user's home.
RUN if [ -x /opt/codex/packages/standalone/current/bin/codex-code-mode-host ]; then \
      ln -sfn /opt/codex/packages/standalone/current/bin/codex-code-mode-host \
        /usr/local/bin/codex-code-mode-host; \
    fi

COPY --chown=root:root docker/codex-config.toml /etc/codex/config.toml
COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/cicada-entrypoint
COPY --from=cicada-builder /out/cicada /usr/local/bin/cicada
RUN chmod 0755 /usr/local/bin/cicada-entrypoint

USER cicada
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cicada-entrypoint"]
CMD ["shell"]
