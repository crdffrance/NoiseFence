#!/usr/bin/env python3
"""Exercise the shipped confinement with synthetic documents in disposable units."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root on a systemd Linux host")
    spec = importlib.util.spec_from_file_location("vision_tests", ROOT / "tests/vision_worker.py")
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    name = "nfvis-test-" + uuid.uuid4().hex[:8]
    directory = Path("/opt") / name
    directory.mkdir(mode=0o755)
    worker = directory / "vision-worker.py"
    shutil.copyfile(ROOT / "deploy/vision-worker.py", worker)
    worker.chmod(0o644)
    units = Path("/etc/systemd/system")
    service_file = units / (name + ".service")
    socket_file = units / (name + ".socket")
    socket_path = "/run/" + name + "/worker.sock"
    try:
        service = (ROOT / "deploy/noisefence-vision.service").read_text().replace(
            "noisefence-vision.socket", name + ".socket").replace(
            "User=noisefence-vision\nGroup=noisefence-vision", "DynamicUser=true\nUser=" + name).replace(
            "/opt/noisefence/current/deploy/vision-worker.py", str(worker))
        service_file.write_text(service)
        socket_unit = (ROOT / "deploy/noisefence-vision.socket").read_text().replace(
            "/run/noisefence-vision/worker.sock", socket_path).replace(
            "SocketUser=noisefence-vision", "SocketUser=root").replace(
            "SocketGroup=noisefence", "SocketGroup=root").replace("SocketMode=0660", "SocketMode=0600")
        socket_file.write_text(socket_unit)
        run("systemctl", "daemon-reload")
        run("systemctl", "start", name + ".socket", name + ".service")
        with tempfile.TemporaryDirectory(prefix=name) as temporary:
            image, payload = tests.fixture(Path(temporary))
            for kind, path in [("image", image), ("pdf", Path(temporary) / "synthetic.pdf")]:
                started = time.monotonic()
                raw = json.dumps(tests.request(path, kind)).encode()
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.settimeout(6)
                    conn.connect(socket_path)
                    conn.sendall(struct.pack("!I", len(raw)) + raw)
                    size = struct.unpack("!I", tests.worker.read_exact(conn, 4))[0]
                    assert 0 < size <= tests.worker.MAX_RESPONSE
                    result = json.loads(tests.worker.read_exact(conn, size))
                assert result["status"] == "complete", result
                assert "NOISEFENCE" in result["pages"][0]["text"], result
                assert payload in [c["data"] for p in result["pages"] for c in p["codes"]], result
                print(json.dumps({"case": "isolated_" + kind, "status": result["status"],
                                  "elapsed_ms": round((time.monotonic() - started) * 1000)}), flush=True)
        assert run("systemctl", "is-active", name + ".service") == "active"
    except Exception:
        print(run("journalctl", "-u", name + ".service", "--no-pager", "-n", "30"), flush=True)
        raise
    finally:
        subprocess.run(["systemctl", "stop", name + ".socket", name + ".service"], check=False)
        socket_file.unlink(missing_ok=True)
        service_file.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
        shutil.rmtree(directory)
        shutil.rmtree(Path(socket_path).parent, ignore_errors=True)


if __name__ == "__main__":
    main()
