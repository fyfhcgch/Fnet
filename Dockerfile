# Fnet in a container: tshark is installed, the WebUI listens on 0.0.0.0
# inside the container (publish it on loopback only, e.g.
# `docker run -p 127.0.0.1:8765:8765`).
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY fnet ./fnet
RUN python -m pip wheel --no-cache-dir --no-deps -w /dist .

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FNET_HOME=/data

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark ca-certificates libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system fnet \
    && useradd --system --gid fnet --home-dir /data --create-home fnet \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap || true

COPY --from=build /dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl \
    && mkdir -p /data /captures \
    && chown -R fnet:fnet /data /captures

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

USER fnet
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3)"

ENTRYPOINT ["/entrypoint.sh"]
