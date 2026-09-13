<a id="antivirus-et-signatures-complémentaires"></a>
# Antivirus and complementary signatures

These optional connectors are disabled when not configured. Primary-scanner malware receives [classification priority](filter-policy.md), with a null decision score (`null`, not zero). In enforcement mode the configured malware policy can quarantine it. Complementary signatures remain advisory. Observation still delivers without tagging or quarantine. Subject changes require separate Proton/ARC validation.

Two processes are planned: ClamAV with the official databases, then an advisory scanner with Sanesesecurity bases. Their scans run in parallel. This separation prevents a first spam match from interrupting the search for malware in an attachment. Sockets must be different and accessible only to service accounts. No ClamD TCP port is required.

## Official databases on Debian

Installing still maintained ClamAV packages for target distribution and checking security advisories. As of September 6, 2026, Debian 13 still offers 1.4.3 and its [security tracking](https://security-tracker.debian.org/tracker/source-package/clamav) reports fixed vulnerabilities in 1.4.6. Do not deploy this old version on incoming messages. The historical Bookworm container tests the protocol; this is not the version chosen for the server.

The deployment uses the [official Cisco Talos 1.4.6](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6) package installed under `/usr/local`. For AMD64, the `clamav-1.4.6.linux.x86_64.deb` package has for SHA256 `d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2`. Check the supplier's published fingerprint before `dpkg -i`, then run `ldconfig`. This package does not create an account, configuration, or systemd services.

Create the `clamav` system account and `/etc/clamav`, `/var/lib/clamav`, `/var/log/clamav` directories, then install `deploy/clamd.conf` and `deploy/freshclam.conf`. Install `deploy/clamav-upstream.service` as `clamav-daemon.service` and `deploy/freshclam-upstream.service` as `clamav-freshclam.service`. Add `noisefence` to the `clamav` group. Start FreshClam, wait for database validation, then start the scanner. The complementary scanner must also use `/usr/local/sbin/clamd` in its systemd unit. Reload tools are in `/usr/local/bin`. Do not run older distribution daemons alongside these services.

The upstream package must be tracked for its security updates; FreshClam updates signatures, not executables. If Debian then provides a corrected version, the following variant uses its native paths and units:

```sh
sudo apt-get install --no-install-recommends clamav clamav-daemon clamav-freshclam clamdscan
sudo cp -an /etc/clamav/clamd.conf /etc/clamav/clamd.conf.before-noisefence
sudo install -m 0644 deploy/clamd.conf /etc/clamav/clamd.conf
sudo install -d /etc/systemd/system/clamav-daemon.service.d /etc/systemd/system/clamav-daemon.socket.d
sudo install -m 0644 deploy/clamav-daemon.override.conf /etc/systemd/system/clamav-daemon.service.d/noisefence.conf
sudo install -m 0644 deploy/clamav-daemon.socket.override.conf /etc/systemd/system/clamav-daemon.socket.d/noisefence.conf
sudo usermod -aG clamav noisefence
sudo systemctl daemon-reload
sudo systemctl enable --now clamav-freshclam.service
```

Wait for the download and validation of the databases in the FreshClam log, then restart `clamav-daemon.socket` and `clamav-daemon.service`. Check the socket permissions, then activate the `[antivirus]` section of the TOML model. Reboot NoiseFence to load its additional groups. Keep a copy of its previous configuration to remove the connector in case of an incident.

The limits provided cover a message of 25 MiB, 100 MiB after decompression, 16 levels, 500 files and 2 seconds of ClamAV work. The client waits for no more than 3 seconds. Exceedances, encrypted archives and errors remain distinct from a healthy result. An incomplete scan prevents the addition of the antispam prefix. Systemd ceilings must be faced with the actual load and update peaks.

<a id="bases-complémentaires"></a>
## Complementary bases

`deploy/fetch-unofficial-sigs.py` downloads the sources of version 8.0.0 and the Sanesesecurity public key, then checks the fingerprints of `deploy/unofficial-sigs.sources.json`. It does not execute and install anything. A key rotation or a source change requires a revision of this manifest.

```sh
python3 deploy/fetch-unofficial-sigs.py /tmp/noisefence-unofficial-sigs
sudo apt-get install --no-install-recommends gnupg rsync curl socat dnsutils
sudo install -d /etc/clamav-unofficial-sigs /usr/local/share/doc/clamav-unofficial-sigs
sudo install -m 0755 /tmp/noisefence-unofficial-sigs/clamav-unofficial-sigs.sh /usr/local/sbin/clamav-unofficial-sigs
sudo install -m 0644 /tmp/noisefence-unofficial-sigs/config/master.conf /etc/clamav-unofficial-sigs/master.conf
sudo install -m 0644 /tmp/noisefence-unofficial-sigs/config/os/os.debian.conf /etc/clamav-unofficial-sigs/os.conf
sudo install -m 0644 /tmp/noisefence-unofficial-sigs/LICENSE /usr/local/share/doc/clamav-unofficial-sigs/LICENSE
sudo install -m 0644 deploy/unofficial-sigs.user.conf /etc/clamav-unofficial-sigs/user.conf
sudo install -d -o clamav -g clamav /var/lib/noisefence-signatures /var/lib/clamav-unofficial-sigs /var/log/clamav-unofficial-sigs
sudo install -d -o clamav -g clamav -m 0700 /var/lib/clamav-unofficial-sigs/gpg-key
sudo install -m 0600 -o clamav -g clamav /tmp/noisefence-unofficial-sigs/sanesecurity-publickey.gpg /var/lib/clamav-unofficial-sigs/gpg-key/publickey.gpg
sudo install -m 0644 deploy/noisefence-signatures.conf /etc/clamav/noisefence-signatures.conf
sudo install -m 0644 deploy/noisefence-signature-scanner.service deploy/noisefence-signatures.service deploy/noisefence-signatures.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start noisefence-signatures.service
```

Check in the log that the databases have been downloaded, checked by GPG and loaded without error. At the first launch, the absence of the scanner to be reloaded is normal: then start `noisefence-signature-scanner.service`, then activate its automatic boot and `noisefence-signatures.timer`. Finally, activate `[signatures]` in NoiseFence and check the two independent results. Do not start the scanner with an empty base directory or cumulate the timer with an upstream cron.

The profile uses Sanesesecurity LOW and its fix list, disables YARA, automatic program upgrades and providers requiring a separate account. Signatures remain advisory, regardless of their label. To add a provider, check its license, authentication method and its effect on false positives before changing the profile.

<a id="contrôles-dexploitation"></a>
## Operational controls

Monitor `clamav-freshclam.service`, the two scanners and `noisefence-signatures.service`: last success, version of the bases actually loaded, GPG errors, memory, latency and incomplete analyses. Alert whether the official daily databases or additional updates have more than 48 hours. Ask `VERSION` on each socket to raise the version of the engine; the update program log provides versions of the additional databases. An active process with old databases does not prove an up-to-date protection.

The FreshClam service has a ceiling of 2 GiB: it loads the new bases to check them before their installation. On 7 September 2026, the old ceiling of 768 MiB caused repeated `oom-kill` stops during this verification. Plan this peak in addition to the scanners and NoiseFence, then monitor the memory actually available on the host. Do not disable the validation of the bases to reduce this need. For an existing installation, a drop-in systemd `clamav-freshclam.service.d/30-database-memory.conf` can contain:

```ini
[Service]
MemoryMax=2G
```

After installing the drop-in, run `systemctl daemon-reload` and then `systemctl restart clamav-freshclam.service`. Check a successful update cycle and the version loaded by ClamD; the `active` status alone is not enough.

`deploy/health-check.py` and the `noisefence-health.service`/`.timer` units control every five minutes services, sockets, daily database date, last Sanessecurity, file, disk, certificate and LLM budget. The report is recorded in `/var/lib/noisefence/operational-health.json` and in the systemd log. An incident causes the unit to fail; connecting this status to the operator's monitoring for notifications. No alert email is sent by this script.

The `tests/clamav/Dockerfile` harness runs a real EICAR scan in a MIME attachment and a healthy scan without sending email. It uses separate volumes for Rust databases and artifacts. `NOISEFENCE_TEST_UNOFFICIAL=1` also tests the download of sources and signatures; respect supplier limitations if a download fails.

References: [ClamD protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html), [versions of clamav-unofficial-sigs](https://github.com/extremeshok/clamav-unofficial-sigs/releases).
