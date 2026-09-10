#!/usr/bin/env python3
"""Bounded local OCR/QR service. Only --job handles untrusted document formats.

The supervisor speaks length-prefixed JSON over a permission-controlled Unix socket.
Each request gets a separate process group, resource limits and a private tempdir.
No decoder receives a URL, original filename, shell command or mail spool access.
"""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import warnings
import xml.etree.ElementTree as ET

PROTOCOL = "noisefence-vision-1"
MAX_REQUEST = 12 * 1024 * 1024
MAX_RESPONSE = 256 * 1024
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "OMP_THREAD_LIMIT": "1",
       "OMP_NUM_THREADS": "1", "HOME": "/nonexistent"}


def result(status="complete", errors=None):
    return {"protocol": PROTOCOL, "status": status, "pages": [],
            "errors": errors or [], "backend_sha256": None}


def capabilities():
    versions = {}
    for name, flag in [("tesseract", "--version"), ("zbarimg", "--version"),
                       ("pdftoppm", "-v"), ("pdfinfo", "-v")]:
        proc = subprocess.run([name, flag], env=ENV, capture_output=True, timeout=2,
                              check=True)
        versions[name] = (proc.stdout + proc.stderr).decode(errors="replace").splitlines()[0]
    import PIL
    versions["pillow"] = PIL.__version__
    trained = {}
    for root in [Path("/usr/share/tesseract-ocr/5/tessdata"),
                 Path("/usr/share/tesseract-ocr/4.00/tessdata")]:
        for lang in ["fra", "eng"]:
            file = root / (lang + ".traineddata")
            if file.is_file():
                trained[lang] = hashlib.sha256(file.read_bytes()).hexdigest()
    if len(trained) != 2:
        raise RuntimeError("missing trained languages")
    versions["traineddata"] = trained
    versions["worker_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    encoded = json.dumps(versions, sort_keys=True).encode()
    return {"protocol": PROTOCOL, "backend_sha256": hashlib.sha256(encoded).hexdigest(),
            "components": versions}


class Limited(Exception):
    pass


def _wait_process(process, timeout):
    """Wait on Linux process exit notifications; callers own kill/reap on error.

    All worker output is file-backed: this helper deliberately does not drain
    pipes. Unsupported kernels/platforms retain Popen's bounded wait.
    """
    deadline = time.monotonic() + timeout
    if process.poll() is not None:
        return process.returncode
    try:
        fd = os.pidfd_open(process.pid)
    except (AttributeError, OSError):
        return process.wait(timeout=max(0, deadline - time.monotonic()))
    try:
        poller = select.poll()
        poller.register(fd, select.POLLIN)
        events = poller.poll(math.ceil(max(0, deadline - time.monotonic()) * 1000))
        if not any(flags & select.POLLIN for _, flags in events):
            # A timeout, unsupported poll event or racing exit still gets one
            # bounded wait. Never restart the original timeout budget.
            return process.wait(timeout=max(0, deadline - time.monotonic()))
        return process.wait(timeout=0)
    finally:
        os.close(fd)


def _file_command(args, directory, deadline, maximum=MAX_RESPONSE, acceptable=(0,)):
    # File-backed output avoids unbounded communicate() allocations. The job's
    # RLIMIT_FSIZE additionally bounds decoder writes before this size check.
    with tempfile.TemporaryFile(dir=directory) as out, tempfile.TemporaryFile(dir=directory) as err:
        with subprocess.Popen(args, env=ENV, stdin=subprocess.DEVNULL,
                              stdout=out, stderr=err) as process:
            try:
                _wait_process(process, max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise Limited("timeout") from None
            except BaseException:
                process.kill()
                raise
            if process.returncode not in acceptable:
                raise Limited("decoder_failed")
            if out.tell() > maximum or err.tell() > MAX_RESPONSE:
                raise Limited("output_limit")
            out.seek(0)
            return out.read(maximum + 1)


def validate_request(req):
    if not isinstance(req, dict) or req.get("protocol") != PROTOCOL:
        raise Limited("invalid_request")
    limits = req.get("limits", {})
    bounds = {"max_pixels": (10000, 16000000), "max_pages": (1, 8),
              "max_text_chars": (100, 32000), "max_codes": (1, 32),
              "timeout_ms": (100, 4000)}
    if set(limits) != set(bounds):
        raise Limited("invalid_limits")
    for key, (minimum, maximum) in bounds.items():
        if type(limits[key]) is not int or not minimum <= limits[key] <= maximum:
            raise Limited("invalid_limits")
    parts = req.get("parts")
    if not isinstance(parts, list) or not 1 <= len(parts) <= 8:
        raise Limited("invalid_parts")
    total = 0
    decoded = []
    for part in parts:
        if not isinstance(part, dict) or part.get("kind") not in ("image", "pdf"):
            raise Limited("invalid_part")
        try:
            data = base64.b64decode(part["data"], validate=True)
        except (ValueError, TypeError, KeyError):
            raise Limited("invalid_encoding") from None
        total += len(data)
        if not 0 < len(data) <= 4 * 1024 * 1024 or total > 8 * 1024 * 1024:
            raise Limited("input_limit")
        decoded.append((part["kind"], data))
    return limits, decoded


def analyze(req, directory):
    from PIL import Image, ImageOps
    limits, parts = validate_request(req)
    Image.MAX_IMAGE_PIXELS = limits["max_pixels"]
    warnings.simplefilter("error", Image.DecompressionBombWarning)
    deadline = time.monotonic() + limits["timeout_ms"] / 1000
    response = result()
    text_left = limits["max_text_chars"]
    codes_left = limits["max_codes"]

    def command(args, maximum=MAX_RESPONSE, acceptable=(0,)):
        return _file_command(args, directory, deadline, maximum, acceptable)

    def page(image, part_index, page_index):
        nonlocal text_left, codes_left
        if len(response["pages"]) >= limits["max_pages"]:
            raise Limited("page_limit")
        if image.width * image.height > limits["max_pixels"] or min(image.size) <= 0:
            raise Limited("pixel_limit")
        normalized = Path(directory) / "page.png"
        image = ImageOps.exif_transpose(image)
        # Flatten transparency on white; never feed ImageMagick the original format.
        rgba = image.convert("RGBA")
        rgb = Image.new("RGB", rgba.size, "white")
        rgb.paste(rgba, mask=rgba.getchannel("A"))
        rgb.save(normalized)
        xml = command(["zbarimg", "--quiet", "--xml", "--nodisplay", str(normalized)],
                      acceptable=(0, 4))
        codes = []
        if xml.strip():
            if b"<!DOCTYPE" in xml.upper() or b"<!ENTITY" in xml.upper():
                raise Limited("invalid_codes")
            try:
                tree = ET.fromstring(xml)
            except ET.ParseError:
                raise Limited("invalid_codes") from None
            for sym in tree.iter():
                if sym.tag.split("}")[-1] != "symbol":
                    continue
                data = "".join(e.text or "" for e in sym if e.tag.split("}")[-1] == "data")
                if len(data) > 4096 or codes_left <= 0:
                    raise Limited("code_limit")
                codes.append({"kind": sym.attrib.get("type", "unknown")[:32], "data": data})
                codes_left -= 1
        text = command(["tesseract", str(normalized), "stdout", "--oem", "1",
                        "-l", "fra+eng", "--psm", "11"]).decode("utf-8", errors="replace").strip()
        bounded = text[:text_left]
        text_left -= len(bounded)
        response["pages"].append({"part": part_index, "page": page_index,
                                  "text": bounded, "codes": codes})
        if len(text) > len(bounded):
            raise Limited("text_limit")

    for index, (kind, data) in enumerate(parts):
        try:
            if time.monotonic() >= deadline:
                raise Limited("timeout")
            if kind == "pdf":
                pdf = Path(directory) / "input.pdf"
                pdf.write_bytes(data)
                info = command(["pdfinfo", str(pdf)], maximum=16384).decode(errors="replace")
                count = next((int(s.split(":", 1)[1]) for s in info.splitlines()
                              if s.startswith("Pages:")), 0)
                if count <= 0:
                    raise Limited("invalid_pdf")
                for number in range(1, min(count, limits["max_pages"]) + 1):
                    if len(response["pages"]) >= limits["max_pages"]:
                        raise Limited("page_limit")
                    prefix = Path(directory) / "pdf-page"
                    # Default RGB PPM has the same raster without PNG encoding.
                    # scale-to 2400 bounds it below 18 MiB, including the header.
                    command(["pdftoppm", "-f", str(number), "-l", str(number), "-singlefile",
                             "-scale-to", "2400", str(pdf), str(prefix)])
                    with Image.open(str(prefix) + ".ppm") as img:
                        page(img, index, number - 1)
                if count > limits["max_pages"]:
                    raise Limited("page_limit")
            else:
                path = Path(directory) / "input.image"
                path.write_bytes(data)
                with Image.open(path) as img:
                    if img.format not in ("PNG", "JPEG", "GIF", "WEBP", "TIFF", "BMP"):
                        raise Limited("unsupported_image")
                    # Bound animated/multipage images before any frame loop.
                    count = getattr(img, "n_frames", 1)
                    for number in range(min(count, limits["max_pages"])):
                        img.seek(number)
                        page(img, index, number)
                    if count > limits["max_pages"]:
                        raise Limited("page_limit")
        except Limited as error:
            response["status"] = "limited"
            response["errors"].append(str(error))
        except Exception:
            response["status"] = "limited"
            response["errors"].append("invalid_document")
        if time.monotonic() >= deadline:
            response["status"] = "limited"
            response["errors"].append("timeout")
            break
    response["errors"] = sorted(set(response["errors"]))
    return response


def job(directory):
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (6, 6))
    resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise Limited("input_limit")
        response = analyze(json.loads(raw), directory)
    except Exception:
        response = result("limited", ["invalid_request"])
    encoded = json.dumps(response, ensure_ascii=True).encode()
    if len(encoded) > MAX_RESPONSE:
        encoded = json.dumps(result("limited", ["output_limit"])).encode()
    sys.stdout.buffer.write(encoded)


def read_exact(conn, size, deadline=None):
    output = bytearray()
    while len(output) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("frame_timeout")
            conn.settimeout(remaining)
        chunk = conn.recv(min(size - len(output), 65536))
        if not chunk:
            raise EOFError()
        output.extend(chunk)
    return output


def supervise(raw, backend):
    with tempfile.TemporaryDirectory(prefix="nf-vision-") as directory:
        with tempfile.TemporaryFile(dir=directory) as input_file, tempfile.TemporaryFile(dir=directory) as output:
            input_file.write(raw)
            input_file.seek(0)
            process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                        "--job", directory], env=ENV,
                                       stdin=input_file, stdout=output, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            try:
                _wait_process(process, 4.5)
            except subprocess.TimeoutExpired:
                pass
            finally:
                # Also reap decoder grandchildren left behind after a job error.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            output.seek(0)
            encoded = output.read(MAX_RESPONSE + 1)
            try:
                if process.returncode != 0 or not encoded or len(encoded) > MAX_RESPONSE:
                    raise ValueError()
                response = json.loads(encoded)
            except (ValueError, UnicodeError):
                response = result("limited", ["worker_limit"])
            response["backend_sha256"] = backend
            return json.dumps(response, ensure_ascii=True).encode()


def serve(path):
    backend = capabilities()["backend_sha256"]
    if path:
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path)
        os.chmod(path, 0o600)
        listener.listen(8)
    else:
        if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
            raise RuntimeError("systemd socket activation required")
        listener = socket.socket(fileno=3)
    while True:
        conn, _ = listener.accept()
        with conn:
            try:
                # One wall-clock budget for the whole frame, not a fresh second
                # for every fragment. A slow client cannot occupy a serial worker
                # indefinitely and starve the other callers of this instance.
                deadline = time.monotonic() + 1
                length = struct.unpack("!I", read_exact(conn, 4, deadline))[0]
                if not 0 < length <= MAX_REQUEST:
                    continue
                encoded = supervise(read_exact(conn, length, deadline), backend)
                if len(encoded) > MAX_RESPONSE:
                    encoded = json.dumps(result("limited", ["output_limit"])).encode()
                conn.settimeout(1)
                conn.sendall(struct.pack("!I", len(encoded)) + encoded)
            except (OSError, EOFError, ValueError):
                # No raw document, payload, text or decoder stderr in the journal.
                continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--serve", action="store_true")
    group.add_argument("--job", metavar="DIRECTORY")
    group.add_argument("--capabilities", action="store_true")
    parser.add_argument("--socket", help="private test socket; production uses systemd")
    args = parser.parse_args()
    os.umask(0o077)
    if args.capabilities:
        print(json.dumps(capabilities(), indent=2))
    elif args.job:
        job(args.job)
    else:
        serve(args.socket)
