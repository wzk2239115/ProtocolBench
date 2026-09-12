# ProtocolBench agent image: multi-tool verification + protocol reference docs.
#
# Provides Tamarin + Verifpal + RFCs/specs for currently-deployed real-world protocols.
# The agent uses these to analyze and attack protocols that are part of the real world RIGHT NOW.
FROM debian:trixie

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        maude libgmp10 graphviz patchelf xz-utils ca-certificates curl \
        python3 python3-pip ripgrep grep sed gawk jq file less vim nano \
        netcat-openbsd tmux git unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Tamarin Prover 1.12.0 ─────────────────────────────────────────────────────
COPY bin/ /tmp/tamarin-dist/
RUN arch="$(dpkg --print-architecture)" && \
    if [ "$arch" = "arm64" ]; then \
        tar xzf /tmp/tamarin-dist/tamarin-prover-1.12.0-arm64.tar.gz -C /opt/ && \
        mv /opt/tamarin-prover/1.12.0/bin/tamarin-prover /usr/local/bin/tamarin-prover && \
        patchelf --set-interpreter /lib/ld-linux-aarch64.so.1 /usr/local/bin/tamarin-prover; \
    elif [ "$arch" = "amd64" ]; then \
        tar xzf /tmp/tamarin-dist/tamarin-prover-1.12.0-amd64.tar.gz -C /tmp/ && \
        mv /tmp/tamarin-prover /usr/local/bin/tamarin-prover; \
    else echo "unsupported: $arch" >&2; exit 1; fi && \
    rm -rf /tmp/tamarin-dist /opt/tamarin-prover && \
    chmod +x /usr/local/bin/tamarin-prover

# ── Verifpal 1.3.6 ───────────────────────────────────────────────────────────
COPY bin/verifpal_amd64.deb bin/verifpal_arm64.deb /tmp/
RUN arch="$(dpkg --print-architecture)" && \
    if [ "$arch" = "amd64" ]; then \
        dpkg -i /tmp/verifpal_amd64.deb; \
    elif [ "$arch" = "arm64" ]; then \
        dpkg -i /tmp/verifpal_arm64.deb; \
    else echo "unsupported: $arch" >&2; exit 1; fi && \
    rm -f /tmp/verifpal_amd64.deb /tmp/verifpal_arm64.deb

# ── Verifpal example models ──────────────────────────────────────────────────
COPY bin/verifpal-examples/ /opt/verifpal-examples/

# ── Protocol reference documents (RFCs + specs for currently-deployed protocols) ──
COPY docs/ /opt/protocol-docs/

# ── Lean 4 ───────────────────────────────────────────────────────────────────
# Lean has far more pretraining data than Tamarin; models are more fluent in
# Lean syntax and proofs always terminate (no backward-search non-termination).
COPY bin/lean-minimal.tar.gz /tmp/lean-minimal.tar.gz
RUN mkdir -p /opt/lean && \
    tar xzf /tmp/lean-minimal.tar.gz -C /opt/lean && \
    ln -sf /opt/lean/bin/lean /usr/local/bin/lean && \
    ln -sf /opt/lean/bin/lake /usr/local/bin/lake && \
    ln -sf /opt/lean/bin/leanc /usr/local/bin/leanc && \
    ln -sf /opt/lean/bin/leanmake /usr/local/bin/leanmake && \
    rm -f /tmp/lean-minimal.tar.gz
ENV LD_LIBRARY_PATH=/opt/lean/lib/lean

# ── Lean OIDC starter library ────────────────────────────────────────────────
COPY lean/ /opt/lean-starter/

# Sanity checks
RUN tamarin-prover --version 2>&1 | grep -q "1.12.0" && \
    verifpal --version 2>&1 | grep -q "1.3" && \
    maude --version | head -1 && \
    lean --version && \
    ls /opt/protocol-docs/

WORKDIR /workspace
CMD ["tail", "-f", "/dev/null"]
