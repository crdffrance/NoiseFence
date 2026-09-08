#!/bin/sh
# Optional Debian/Ubuntu OCR service. Run after installing a NoiseFence release.
set -eu
if [ "$(id -u)" != 0 ]; then echo 'Run as root.' >&2; exit 1; fi
bundle=/opt/noisefence/current
test -f "$bundle/deploy/vision-worker.py"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-fra tesseract-ocr-eng zbar-tools python3-pil poppler-utils
if ! id noisefence-vision >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin noisefence-vision
fi
install -m 0644 "$bundle/deploy/noisefence-vision.socket" /etc/systemd/system/
install -m 0644 "$bundle/deploy/noisefence-vision.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now noisefence-vision.socket
systemctl restart noisefence-vision.service
systemctl is-active noisefence-vision.socket noisefence-vision.service
/usr/bin/python3 "$bundle/deploy/vision-worker.py" --capabilities
echo 'Configure [vision], check-config, then restart noisefence to enable OCR.'
