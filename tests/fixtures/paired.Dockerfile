FROM postgres@sha256:d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f
RUN apt-get update -qq && apt-get install -y --no-install-recommends systemd systemd-sysv python3 ca-certificates openssl && rm -rf /var/lib/apt/lists/* && systemctl mask systemd-binfmt.service proc-sys-fs-binfmt_misc.mount
RUN apt-get update -qq && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/* && systemctl mask ssh.service ssh.socket
RUN truncate -s 0 /etc/machine-id && rm -f /var/lib/dbus/machine-id
LABEL org.noisefence.test-fixture="paired-release-lifecycle"
ENV container=docker
ENTRYPOINT []
CMD ["/sbin/init"]
