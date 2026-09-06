FROM rust:1.98-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
RUN apt-get update && apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam clamdscan python3 gnupg rsync curl socat dnsutils && rm -rf /var/lib/apt/lists/*
COPY deploy/clamd.conf /etc/clamav/clamd.conf
COPY deploy /opt/noisefence-deploy
COPY tests/clamav/run.sh /usr/local/bin/noisefence-test-clamav
WORKDIR /src
ENTRYPOINT ["sh", "/usr/local/bin/noisefence-test-clamav"]
