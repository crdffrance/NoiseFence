"""Linux C API phase probe on a generated public image; not a mail decoder.

Run in a private, resource-limited unit with the worker decoder dependencies.
No user documents are read. Output is timings and hashes, never recognized text.
"""
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import statistics
import tempfile
import time

root = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

worker = module('probe_worker', root/'deploy/vision-worker.py')
fixtures = module('probe_fixtures', root/'tests/vision_worker.py')
os.environ.update(worker.ENV)
resource.setrlimit(resource.RLIMIT_AS, (768*1024*1024,)*2)
resource.setrlimit(resource.RLIMIT_FSIZE, (32*1024*1024,)*2)
resource.setrlimit(resource.RLIMIT_NOFILE, (64,)*2)
tess = C.CDLL('libtesseract.so.5')
lept = C.CDLL('libleptonica.so.6')
def bind(lib, name, restype, *args):
    value = getattr(lib, name); value.restype = restype; value.argtypes = list(args)
    return value

create = bind(tess, 'TessBaseAPICreate', C.c_void_p)
delete = bind(tess, 'TessBaseAPIDelete', None, C.c_void_p)
init = bind(tess, 'TessBaseAPIInit2', C.c_int, C.c_void_p, C.c_char_p, C.c_char_p, C.c_int)
psm = bind(tess, 'TessBaseAPISetPageSegMode', None, C.c_void_p, C.c_int)
set_name = bind(tess, 'TessBaseAPISetInputName', None, C.c_void_p, C.c_char_p)
set_image = bind(tess, 'TessBaseAPISetImage2', None, C.c_void_p, C.c_void_p)
recognize = bind(tess, 'TessBaseAPIRecognize', C.c_int, C.c_void_p, C.c_void_p)
get_text = bind(tess, 'TessBaseAPIGetUTF8Text', C.c_void_p, C.c_void_p)
delete_text = bind(tess, 'TessDeleteText', None, C.c_void_p)
pix_read = bind(lept, 'pixRead', C.c_void_p, C.c_char_p)
pix_destroy = bind(lept, 'pixDestroy', None, C.POINTER(C.c_void_p))
records = []
with tempfile.TemporaryDirectory(prefix='nf-tess-profile-') as name:
    out = Path(name)
    image, _ = fixtures.fixture(out)
    from PIL import Image, ImageOps
    with Image.open(image) as source:
        source = ImageOps.exif_transpose(source)
        rgba = source.convert('RGBA'); rgb = Image.new('RGB', rgba.size, 'white')
        rgb.paste(rgba, mask=rgba.getchannel('A'))
        normalized = out/'page.png'; rgb.save(normalized)
    expected = worker._file_command(['tesseract', str(normalized), 'stdout', '--oem', '1', '-l', 'fra+eng', '--psm', '11'], out, time.monotonic()+4).decode().strip()
    assert 'NOISEFENCE' in expected and 'Bonjour' in expected
    for iteration in range(8):
        handle = create(); pix = C.c_void_p(); text_pointer = None
        assert handle
        stages = {}
        started = time.monotonic()
        try:
            start = time.monotonic()
            assert init(handle, None, b'fra+eng', 1) == 0
            psm(handle, 11)
            stages['init_ms'] = (time.monotonic()-start)*1000
            start = time.monotonic()
            pix = C.c_void_p(pix_read(os.fsencode(normalized))); assert pix.value
            set_name(handle, os.fsencode(normalized)); set_image(handle, pix)
            stages['read_set_image_ms'] = (time.monotonic()-start)*1000
            start = time.monotonic()
            assert recognize(handle, None) == 0
            stages['recognize_ms'] = (time.monotonic()-start)*1000
            start = time.monotonic()
            text_pointer = get_text(handle); assert text_pointer
            text = C.string_at(text_pointer).decode().strip()
            assert text == expected
            stages['get_text_ms'] = (time.monotonic()-start)*1000
        finally:
            if text_pointer: delete_text(text_pointer)
            delete(handle)
            if pix.value: pix_destroy(C.byref(pix))
        stages['total_ms'] = (time.monotonic()-started)*1000
        stages['iteration'] = iteration
        records.append(stages)
    report = {'schema':'noisefence-tesseract-profile-1', 'scope':'Eight freshly initialized C API handles within one process, one synthetic normalized PNG, warmed library/model caches. Excludes process start, page normalization, barcode recognition and SMTP. Exact text equality to CLI checked. Not a production implementation or quality measurement.', 'capabilities':worker.capabilities(), 'fixture_sha256':hashlib.sha256(image.read_bytes()).hexdigest(), 'normalized_sha256':hashlib.sha256(normalized.read_bytes()).hexdigest(), 'text_sha256':hashlib.sha256(expected.encode()).hexdigest(), 'records':records, 'median_ms':{key:statistics.median(r[key] for r in records) for key in records[0] if key!='iteration'}}
    print(json.dumps(report), flush=True)
