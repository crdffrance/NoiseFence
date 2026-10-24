#!/bin/sh
# Isolated native tests only. Publish qualification.json, never the fixture tree.
set -eu
umask 077
platform=${1:?Usage: check_release_lifecycle.sh PLATFORM ARCHIVE FIXTURE OUTPUT}
archive=${2:?Candidate archive required}
fixture=${3:?Fresh synthetic baseline fixture required}
output=${4:?New output directory required}
case "$platform" in linux-amd64|linux-arm64) ;; *) exit 2;; esac
confinement=${NOISEFENCE_REHEARSAL_APPARMOR:-0}
case "$confinement" in 0|1) ;; *) exit 2;; esac
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
    if [ "$status" -ne 0 ]; then
        printf 'Native lifecycle failed: phase=%s exit=%s; raw fixture data was not uploaded.\n' "$phase" "$status" >&2
        python3 scripts/rehearsal_diagnostics.py "$output" "$phase" || true
    fi
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
if [ "$confinement" = 1 ]; then
    phase=socket-boundary
    printf 'Native lifecycle: %s\n' "$phase"
    rustc --edition=2024 --test tests/fixtures/postgres_socket_probe.rs -o "$output/socket-probe-tests" > "$output/socket-boundary.log" 2>&1
    "$output/socket-probe-tests" >> "$output/socket-boundary.log" 2>&1
    rustc --edition=2024 tests/fixtures/postgres_socket_probe.rs -o "$output/socket-probe" >> "$output/socket-boundary.log" 2>&1
    python3 tests/confinement_socket_probe.py --binary "$output/socket-probe" --image "$name-paired" --output "$output/socket-boundary" >> "$output/socket-boundary.log" 2>&1
fi
phase=standalone
printf 'Native lifecycle: %s\n' "$phase"
python3 tests/release_lifecycle.py --old-archive "$output/baseline/noisefence-$baseline-$platform.tar.gz" --new-archive "$archive" --image "$name-standalone" --platform "$docker_platform" --output "$output/standalone" > "$output/standalone.log" 2>&1
phase=paired
printf 'Native lifecycle: %s\n' "$phase"
if [ "$confinement" = 1 ]; then
    python3 tests/confined_paired_release.py --old-archive "$output/baseline/noisefence-$baseline-$platform.tar.gz" --new-archive "$archive" --image "$name-paired" --platform "$docker_platform" --fixture "$fixture" --output "$output/paired" --evidence "$output/apparmor" > "$output/paired.log" 2>&1
else
    python3 tests/paired_release_lifecycle.py --old-archive "$output/baseline/noisefence-$baseline-$platform.tar.gz" --new-archive "$archive" --archive-candidate --image "$name-paired" --platform "$docker_platform" --fixture "$fixture" --output "$output/paired" > "$output/paired.log" 2>&1
fi
phase=summary
printf 'Native lifecycle: %s\n' "$phase"
python3 scripts/release_rehearsal.py summarize --platform "$platform" --archive "$archive" --directory "$output"
