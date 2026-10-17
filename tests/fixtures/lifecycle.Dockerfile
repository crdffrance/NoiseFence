FROM postgres@sha256:d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f
RUN apt-get update -qq && apt-get install -y --no-install-recommends systemd systemd-sysv python3 ca-certificates openssl && rm -rf /var/lib/apt/lists/* && systemctl mask systemd-binfmt.service proc-sys-fs-binfmt_misc.mount
LABEL org.noisefence.test-fixture="release-lifecycle"
ENV container=docker
ENTRYPOINT []
CMD ["/sbin/init"]
