#!/usr/bin/env python3
"""Real OCR/QR/PDF and resource-limit checks, entirely synthetic and local."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vision_worker", ROOT / "deploy/vision-worker.py")
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def fixture(directory):
    from PIL import Image, ImageDraw, ImageFont
    qr = directory / "qr.png"
    payload = "https://login.example.invalid/verify?token=SYNTHETIC_ONLY"
    subprocess.run(["qrencode", "-s", "8", "-m", "4", "-o", str(qr), payload], check=True)
    img = Image.new("RGB", (1300, 650), "white")
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 34)
    draw = ImageDraw.Draw(img)
    draw.text((30, 25), "NOISEFENCE URGENT PASSWORD VERIFICATION", font=font, fill="black")
    draw.text((30, 85), "Bonjour, vérifiez votre compte immédiatement.", font=font, fill="black")
    with Image.open(qr) as code:
        img.paste(code, (40, 150))
    path = directory / "synthetic.png"
    img.save(path)
    save_pdf_fixture(img, directory / "synthetic.pdf")
    return path, payload


def save_pdf_fixture(image, path):
    """Write only generated test material, with a standards-range free entry.

    Pillow 11.1 emits generation 65536 for object zero. Correct that fixed-width
    xref field to 65535, without changing object offsets, streams or page pixels.
    This helper is never used to repair or accept an incoming user document.
    """
    image.save(path, "PDF", resolution=150)
    raw = path.read_bytes()
    offset = int(raw.rsplit(b"startxref\n", 1)[1].splitlines()[0])
    header, section, entry = raw[offset:].splitlines()[:3]
    assert header == b"xref" and section.startswith(b"0 ")
    assert entry in (b"0000000000 65535 f ", b"0000000000 65536 f ")
    start = offset + len(header) + len(section) + 2
    if b"65536" in entry:
        raw = raw[:start] + entry.replace(b"65536", b"65535") + raw[start+len(entry):]
        path.write_bytes(raw)


def request(path, kind="image", **limits):
    return {"protocol": worker.PROTOCOL, "limits": {
        "timeout_ms": 4000, "max_pixels": 8_000_000, "max_pages": 4,
        "max_text_chars": 16000, "max_codes": 16, **limits},
        "parts": [{"kind": kind, "data": base64.b64encode(path.read_bytes()).decode()}]}


class WorkerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="nf-vision-test-")
        cls.root = Path(cls.temp.name)
        cls.image, cls.payload = fixture(cls.root)
        cls.backend = worker.capabilities()["backend_sha256"]
        cls.socket = str(cls.root / "worker.sock")
        cls.process = subprocess.Popen([sys.executable, str(ROOT / "deploy/vision-worker.py"),
                                        "--serve", "--socket", cls.socket],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while not Path(cls.socket).exists():
            if cls.process.poll() is not None:
                raise AssertionError(cls.process.stderr.read().decode())
            if time.monotonic() > deadline:
                raise AssertionError("worker socket startup timeout")
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=6)
        cls.process.stderr.close()
        cls.temp.cleanup()

    def call(self, req):
        raw = json.dumps(req).encode()
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(6)
            conn.connect(self.socket)
            conn.sendall(struct.pack("!I", len(raw)) + raw)
            size = struct.unpack("!I", worker.read_exact(conn, 4))[0]
            self.assertLessEqual(size, worker.MAX_RESPONSE)
            return json.loads(worker.read_exact(conn, size))

    def test_image_ocr_and_exact_qr(self):
        started = time.monotonic()
        result = self.call(request(self.image))
        self.assertEqual(result["status"], "complete", result)
        text = " ".join(p["text"] for p in result["pages"])
        self.assertIn("NOISEFENCE", text)
        self.assertIn("PASSWORD", text)
        self.assertIn("Bonjour", text)
        codes = [c for p in result["pages"] for c in p["codes"]]
        self.assertIn({"kind": "QR-Code", "data": self.payload}, codes)
        self.assertEqual(result["backend_sha256"], self.backend)
        print(json.dumps({"case": "image_ocr_qr", "elapsed_ms": round((time.monotonic()-started)*1000),
                          "pages": len(result["pages"]), "codes": len(codes)}))

    def test_scanned_pdf(self):
        started = time.monotonic()
        result = self.call(request(self.root / "synthetic.pdf", "pdf"))
        self.assertEqual(result["status"], "complete", result)
        self.assertIn("NOISEFENCE", result["pages"][0]["text"])
        self.assertIn(self.payload, [c["data"] for c in result["pages"][0]["codes"]])
        print(json.dumps({"case": "scanned_pdf", "elapsed_ms": round((time.monotonic()-started)*1000)}))

    def test_pdf_intermediate_matches_former_png_raster_pixel_for_pixel(self):
        from PIL import Image
        color_pdf = self.root/"color.pdf"
        pattern = bytes((i*37)%256 for i in range(97*53*3))
        save_pdf_fixture(Image.frombytes("RGB", (97,53), pattern), color_pdf)
        for pdf in [self.root/"synthetic.pdf", color_pdf]:
            with self.subTest(pdf=pdf.name):
                for extension, options in [("ppm", []), ("png", ["-png"])]:
                    worker._file_command(["pdftoppm", "-f", "1", "-l", "1", "-singlefile",
                        "-scale-to", "2400", *options, str(pdf), str(self.root / ("raster-"+extension))],
                        self.root, time.monotonic()+4)
                self.assertLess((self.root/"raster-ppm.ppm").stat().st_size, 18*1024*1024)
                with Image.open(self.root/"raster-ppm.ppm") as ppm, Image.open(self.root/"raster-png.png") as png:
                    self.assertEqual(ppm.size, png.size)
                    self.assertEqual(ppm.mode, png.mode)
                    self.assertEqual(ppm.tobytes(), png.tobytes())

    def test_mixed_parts_keep_original_part_and_page_indexes(self):
        req = request(self.image)
        req["parts"].extend(request(self.root/"synthetic.pdf", "pdf")["parts"])
        response = self.call(req)
        self.assertEqual(response["status"], "complete", response)
        self.assertEqual([(p["part"], p["page"]) for p in response["pages"]], [(0,0), (1,0)])
        for page in response["pages"]:
            self.assertIn("NOISEFENCE", page["text"])
            self.assertIn(self.payload, [c["data"] for c in page["codes"]])

    def test_corrupt_and_oversized_input_are_not_clean(self):
        req = request(self.image)
        req["parts"][0]["data"] = base64.b64encode(b"invalid image").decode()
        self.assertEqual(self.call(req)["status"], "limited")
        req["parts"][0]["data"] = "!!!"
        self.assertEqual(self.call(req)["status"], "limited")
        req = request(self.image, max_pixels=10000)
        self.assertEqual(self.call(req)["status"], "limited")
        req = request(self.image, max_text_chars=100)
        self.assertEqual(self.call(req)["status"], "limited")

    def test_plain_image_without_barcode_is_success_and_frames_are_bounded(self):
        from PIL import Image
        blank = Image.new("RGB", (200, 200), "white")
        path = self.root / "blank.png"
        blank.save(path)
        result = self.call(request(path))
        self.assertEqual(result["status"], "complete", result)
        self.assertEqual(result["pages"][0]["codes"], [])
        animated = self.root / "frames.tiff"
        blank.save(animated, save_all=True, append_images=[blank.copy()] * 2)
        result = self.call(request(animated, max_pages=1))
        self.assertEqual(result["status"], "limited", result)
        self.assertIn("page_limit", result["errors"])

    def test_invalid_frame_does_not_kill_service(self):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(1)
            conn.connect(self.socket)
            conn.sendall(struct.pack("!I", worker.MAX_REQUEST + 1))
            self.assertEqual(conn.recv(1), b"")
        self.assertEqual(self.call({"protocol": "bad"})["status"], "limited")
        self.assertIsNone(self.process.poll())


if __name__ == "__main__":
    unittest.main(verbosity=2)
