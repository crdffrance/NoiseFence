#!/bin/sh
# Isolated native tests only. Publish qualification.json, never the fixture tree.
set -eu
umask 077
platform=${1:?Usage: check_release_lifecycle.sh PLATFORM ARCHIVE FIXTURE OUTPUT}
archive=${2:?Candidate archive required}
fixture=${3:?Fresh synthetic baseline fixture required}
output=${4:?New output directory required}
case "$platform" in linux-amd64|linux-arm64) ;; *) exit 2;; esac
docker_platform="linux/${platform#linux-}"
mkdir -p "$(dirname "$output")"
mkdir -m 0700 "$output"
phase=baseline
printf 'Native lifecycle: %s\n' "$phase"
python3 scripts/release_rehearsal.py fetch --platform "$platform" --directory "$output/baseline"
baseline=$(python3 scripts/release_rehearsal.py baseline-version)
name="nf-release-test-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:12])')"
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then printf 'Native lifecycle failed: phase=%s exit=%s; raw fixture data was not uploaded.\n' "$phase" "$status" >&2; fi
    docker image rm "$name-paired" "$name-standalone" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup 0
phase=paired-image
printf 'Native lifecycle: %s\n' "$phase"
docker build --platform "$docker_platform" --file tests/fixtures/paired.Dockerfile --tag "$name-paired" . > "$output/paired-image.log" 2>&1
phase=standalone-image
printf 'Native lifecycle: %s\n' "$phase"
docker build --platform "$docker_platform" --file tests/fixtures/lifecycle.Dockerfile --tag "$name-standalone" . > "$output/standalone-image.log" 2>&1
phase=standalone
printf 'Native lifecycle: %s\n' "$phase"
python3 tests/release_lifecycle.py --old-archive "$output/baseline/noisefence-$baseline-$platform.tar.gz" --new-archive "$archive" --image "$name-standalone" --platform "$docker_platform" --output "$output/standalone" > "$output/standalone.log" 2>&1
phase=paired
printf 'Native lifecycle: %s\n' "$phase"
python3 tests/paired_release_lifecycle.py --old-archive "$output/baseline/noisefence-$baseline-$platform.tar.gz" --new-archive "$archive" --archive-candidate --image "$name-paired" --platform "$docker_platform" --fixture "$fixture" --output "$output/paired" > "$output/paired.log" 2>&1
phase=summary
printf 'Native lifecycle: %s\n' "$phase"
python3 scripts/release_rehearsal.py summarize --platform "$platform" --archive "$archive" --directory "$output"
