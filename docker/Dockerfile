FROM golang:1.22-alpine AS cicada-builder

ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG ALL_PROXY
ARG NO_PROXY

ENV http_proxy=${HTTP_PROXY} \
    https_proxy=${HTTPS_PROXY} \
    all_proxy=${ALL_PROXY} \
    no_proxy=${NO_PROXY}

WORKDIR /src
COPY cicada-go/go.mod cicada-go/go.sum ./
RUN go mod download
COPY cicada-go/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/cicada ./cmd/cicada

FROM ubuntu:24.04

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG TZ=Etc/UTC
ARG CICADA_UID=1000
ARG CICADA_GID=1000
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
         sh \
    && codex --version

# The standalone package also ships the code-mode helper. The installer cannot
# create this alias when CODEX_HOME differs from the runtime user's home.
RUN ln -s /opt/codex/packages/standalone/current/bin/codex-code-mode-host \
    /usr/local/bin/codex-code-mode-host

COPY --chown=root:root docker/codex-config.toml /etc/codex/config.toml
COPY --chown=root:root docker/entrypoint.sh /usr/local/bin/cicada-entrypoint
COPY --from=cicada-builder /out/cicada /usr/local/bin/cicada
RUN chmod 0755 /usr/local/bin/cicada-entrypoint

USER cicada
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/cicada-entrypoint"]
CMD ["shell"]
