#!/usr/bin/env python3
"""Exercise the real, pinned Rspamd scanner with synthetic mail and no network."""
import argparse
import email.utils
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "rspamd/rspamd:4.1.5@sha256:c307774c4c83bc445f0ae6696fd1798c92b0b89355ae1d87c9c39694c875e51e"


def run(*args, data=None, timeout=90):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed: {args[:4]}\n{result.stdout.decode(errors='replace')[-2000:]}\n{result.stderr.decode(errors='replace')[-2000:]}")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=IMAGE)
    args = parser.parse_args()
    name = "noisefence-rspamd-test-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="noisefence-rspamd-") as directory:
        os.chmod(directory, 0o755)
        mounts = ["-v", f"{directory}:/nf-test"]
        variables = ["--var=LOCAL_CONFDIR=/nf-test/profile", "--var=DBDIR=/var/lib/rspamd", "--var=RUNDIR=/run/noisefence-rspamd"]
        run("docker", "run", "--rm", "--network", "none", "--user", "0", *mounts,
            "-v", f"{ROOT / 'deploy'}:/nf-deploy:ro", "--entrypoint", "/bin/sh", args.image,
            "/nf-deploy/rspamd-profile.sh", "/nf-test/profile", "127.0.0.1")
        config = json.loads(run("docker", "run", "--rm", "--network", "none", *mounts,
            "--entrypoint", "/usr/bin/rspamadm", args.image, *variables, "configdump", "-c", "/nf-test/profile/rspamd.conf", "-j"))
        assert not config.get("classifier"), "No untrained classifier may run"
        workers = config["worker"] if isinstance(config["worker"], list) else [config["worker"]]
        assert workers == [{"normal": {"enabled": True, "bind_socket": "127.0.0.1:11333", "count": 1, "max_tasks": 8, "allow_file_and_shm_inputs": False, "timeout": 6.0, "task_timeout": 5.0}}]
        for module in ["rbl", "fuzzy_check", "gpt", "neural", "neural_autolearn", "url_redirector", "external_services", "metadata_exporter", "history_redis", "rspamd_update", "dkim_signing", "antivirus", "aws_s3"]:
            assert module not in config or config[module].get("enabled") is False, module
        assert config["options"]["max_message"] == 8388608
        assert config["options"]["history_rows"] == 0
        assert config["dmarc"]["reporting"]["enabled"] is False
        assert config["phishing"]["phishtank_enabled"] is False
        for value in config["mid"]["source"]["url"] + config["mime_types"]["file"]:
            assert value.startswith("/"), value
        try:
            run("docker", "run", "--detach", "--name", name, "--network", "none", "--memory", "384m",
                "--cpus", "0.5", "--pids-limit", "32", "--read-only", "--cap-drop", "ALL", "--user", "11333:11333",
                "--tmpfs", "/run/noisefence-rspamd:uid=11333,gid=11333,mode=0700",
                "--tmpfs", "/var/lib/rspamd:uid=11333,gid=11333,mode=0700,size=96m",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", *mounts,
                "--entrypoint", "/usr/bin/rspamd", args.image, "-f", "-c", "/nf-test/profile/rspamd.conf", *variables)
            deadline = time.monotonic() + 20
            while True:
                # rspamc has no `ping` command. A local GTUBE probe exercises
                # the normal scanner without waiting on DNS or sending mail.
                ready = subprocess.run(["docker", "exec", "-i", name, "rspamc", "-h", "127.0.0.1:11333", "-t", "1", "-j"],
                    input=b"Subject: Readiness probe\r\n\r\nXJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n", capture_output=True, timeout=5)
                if ready.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Local scanner did not start")
                time.sleep(0.2)
            base = ("From: Sender <sender@example.test>\r\nTo: Alice <alice@example.test>\r\n"
                    f"Date: {email.utils.formatdate(usegmt=True)}\r\n"
                    "Message-ID: <synthetic@example.test>\r\nSubject: Local comparison test\r\n"
                    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nThe meeting is at ten.\r\n").encode()
            results = []
            for kind, body in [("plain", base), ("gtube", base + b"XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n")]:
                result = json.loads(run("docker", "exec", "-i", name, "rspamc", "-h", "127.0.0.1:11333", "-j", "-p",
                    "-i", "127.0.0.1", "--helo", "sender.example.test", "-F", "sender@example.test", "-r", "alice@example.test", data=body, timeout=15))
                assert isinstance(result["score"], (float, int)) and result["required_score"] > 0
                assert isinstance(result["symbols"], dict)
                if kind == "gtube":
                    assert "GTUBE" in result["symbols"] and result["action"] == "reject"
                    assert result["is_skipped"] is True
                else:
                    assert result["is_skipped"] is False
                results.append({"sample": kind, "score": result["score"], "action": result["action"], "symbols": len(result["symbols"]), "skipped": result["is_skipped"]})
            print(json.dumps({"image": args.image, "profile": (Path(directory)/"profile/profile-id").read_text().strip(), "samples": results}))
        except BaseException:
            logs = subprocess.run(["docker", "logs", "--tail", "30", name], capture_output=True)
            print(logs.stdout.decode(errors="replace") + logs.stderr.decode(errors="replace"), flush=True)
            raise
        finally:
            # This unique container and its anonymous test state are owned by this run.
            subprocess.run(["docker", "rm", "--force", "--volumes", name], capture_output=True)


if __name__ == "__main__":
    main()
