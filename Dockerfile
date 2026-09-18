# syntax=docker/dockerfile:1
FROM node:24-bookworm-slim@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553 AS console
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npx tsc --noEmit && npm run build

FROM rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS engine
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
COPY Cargo.toml Cargo.lock build.rs build_support.rs ./
COPY src/ src/
COPY examples/ examples/
COPY research/semantic-protocol.json research/fusion-protocol.json research/quality-protocol.json research/encoder-runtime.lock.json research/
COPY deploy/vision-worker.py deploy/update-url-feed.py deploy/
COPY scripts/collect_licenses.py scripts/
COPY --from=console /build/web/package-lock.json web/package-lock.json
COPY --from=console /build/web/node_modules web/node_modules
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,id=noisefence-target-${TARGETARCH},target=/build/target \
    cargo build --release --locked --features semantic \
    && cp target/release/noisefence /build/noisefence \
    && python3 scripts/collect_licenses.py

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 noisefence \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/noisefence --shell /usr/sbin/nologin noisefence \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/noisefence \
    && install -d -m 0755 /etc/noisefence /opt/noisefence/web
COPY --from=engine /build/noisefence /usr/local/bin/noisefence
COPY --from=console /build/web/dist/client/ /opt/noisefence/web/
COPY LICENSE THIRD_PARTY.md Cargo.lock /usr/share/doc/noisefence/
COPY licenses/ /usr/share/doc/noisefence/licenses/
COPY --from=engine /build/release/third-party-licenses/ /usr/share/doc/noisefence/third-party-licenses/
COPY config/docker.example.toml /etc/noisefence/config.toml
COPY --chmod=0755 deploy/container-entrypoint.sh /usr/local/bin/noisefence-container-entrypoint
LABEL org.opencontainers.image.title="NoiseFence" \
      org.opencontainers.image.description="Rust SMTP security gateway and management console" \
      org.opencontainers.image.source="https://github.com/crdffrance/NoiseFence" \
      org.opencontainers.image.licenses="GPL-3.0-only"
USER 10001:10001
WORKDIR /opt/noisefence
EXPOSE 2525 18080
ENV NOISEFENCE_HEALTH_URL=http://127.0.0.1:18080/healthz
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD curl --fail --silent "$NOISEFENCE_HEALTH_URL" || exit 1
ENTRYPOINT ["/usr/local/bin/noisefence-container-entrypoint"]
CMD ["serve"]


# Optional offline worker image; the default final image remains the SMTP runtime.
FROM runtime AS calibration
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* && python3 -m venv /opt/noisefence-learning
COPY research/requirements.txt /tmp/research-requirements.txt
RUN /opt/noisefence-learning/bin/pip install --no-cache-dir -r /tmp/research-requirements.txt && rm /tmp/research-requirements.txt
COPY research/train_quality.py research/train_fusion.py research/compare_quality.py research/evaluate_quality.py research/run_quality.py research/quality_metrics.py research/quality_runtime.py research/quality-protocol.json research/fusion-protocol.json /usr/local/bin/research/
COPY deploy/quality-worker.py /usr/local/lib/noisefence-quality-worker.py
USER 10001:10001
HEALTHCHECK NONE
ENTRYPOINT ["/usr/bin/python3", "/usr/local/lib/noisefence-quality-worker.py"]
CMD ["--binary", "/usr/local/bin/noisefence", "--loop"]

FROM runtime AS release
