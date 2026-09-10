# SMTP, MIME and research-detector fuzzing

The `fuzz` workspace uses `libfuzzer-sys` and the local NoiseFence library. It has
its own lockfile. Fuzzing exercises parser behavior and invariants; a finite run
without a crash is not a security certification or a coverage percentage.

| Target | Calls / scope |
| --- | --- |
| `message` | SMTP wire-message validation, subject rewriting, mailing observations, feature extraction and domain extraction |
| `smtp` | SMTP path parsing and bounded async line reading; 2048-byte input guard |
| `protection` | Local protection observations and their report bound; no claim of a live SMTP session |
| `research_detectors` | Compiled heuristic runtime plus bounded content inspection through `research_engines::Runtime::offline` |

The new target extends actual RFC 5322/MIME and attachment parsing. It does not
exercise a live socket dialogue, SMTP authentication, durable delivery, sandbox
execution, the async worker semaphore, or timeout cancellation. The existing SMTP
target and integration tests cover different paths.

## Research target design and budgets

`fuzz/fuzz_targets/research_detectors.rs` caches a compiled `research_engines::Runtime`
and its fixed observation settings in `OnceLock`. Regex compilation and TOML
configuration loading happen once per process. The development configuration is
embedded at build time; the offline method does not open its paths, databases,
DNS/HTTP connections or sockets, and sandbox preparation is explicitly disabled.

Every input first reaches both detectors as raw message bytes. For nonempty
inputs, byte zero also selects a second fixed MIME envelope; the remaining bytes
form its body. This gives mutations access to deeper structural parsers without
requiring them to rediscover valid headers first. There is no UTF-8 gate on the
fuzzer input and malformed parser inputs are retained for coverage.

| Selector modulo 12 | Second-pass MIME body |
| ---: | --- |
| 0 | text/plain |
| 1 | text/html |
| 2 | application/pdf |
| 3 | image/png |
| 4 | image/jpeg |
| 5 | image/gif |
| 6 | Office OpenXML ZIP |
| 7 | legacy Office CFB |
| 8 | multipart/mixed, boundary `fuzz` |
| 9 | message/rfc822 |
| 10 | text/html with base64 transfer encoding |
| 11 | text/html with quoted-printable transfer encoding |

Inputs over **65,536 bytes are rejected before runtime initialization**. The
second envelope and its payload together also fit 65,536 bytes; an oversized
payload suffix is omitted. `-max_len=65536` is an additional libFuzzer control,
not a substitute for the target guard.

Each detector invocation uses these budgets:

| Resource | Heuristics | Content inspection |
| --- | ---: | ---: |
| Raw message | 64 KiB | 64 KiB |
| Header bytes | 4 KiB | 4 KiB |
| Headers / MIME entities | 32 headers, 16 parts | 16 parts, nesting 4 |
| Individual decoded part | 32 KiB | 32 KiB |
| Aggregate input / decoded bytes | 32 KiB regex input | 64 KiB MIME decoded bytes |
| HTML | 2048 traversed nodes | 16 KiB input before DOM construction |
| Structure / nesting | 16 segments | 2048 nodes, nesting 12 |
| ZIP / CFB entries | Not inspected | 16 per container |
| Inflation / total unpacked bytes | Not performed | 32 KiB / 64 KiB |
| Compression ratio | Not applicable | 20 |
| Findings | 16 | 32 |
| Regex matches | 4 per rule, 32 total | Not applicable |
| Image thresholds | Not applicable | 1,000,000 pixels, 8 images |

There are at most two invocations per fuzzer input, so aggregate work can be twice
a per-invocation bound. Built-in regex compilation keeps the detector's validated
fixed defaults. Parser metadata, transient buffers, DOM construction and CFB
initialization add memory overhead. These budgets are not an RSS limit or a
wall-clock deadline; use libFuzzer process controls as well. See
[content-inspection.md](content-inspection.md) for exact parsing and decompression
limits and unsupported formats.

The target asserts observation mode with zero production contribution, finite
bounded candidate weights, configured-only heuristic metadata, match/findings
ceilings, consistent content counters, unique part indices/findings, correct
truncation status, and JSON serialization/deserialization. It distinguishes an
execution that returned normally from a detector that completed inspection.
Panics/assertion failures are left visible to libFuzzer, not caught or converted
into success. Each serialized report is also capped at 64 KiB by an assertion.

## Lockfile and normal tooling

Refresh only the fuzz workspace's dependency closure, offline:

```sh
cargo update --manifest-path fuzz/Cargo.toml --offline -p noisefence
cargo metadata --manifest-path fuzz/Cargo.toml --offline --locked --no-deps
cargo check --manifest-path fuzz/Cargo.toml --offline --locked --bin research_detectors
```

This keeps the path package at `0.5.0-dev.1` and includes the CFB, ZIP, XML and
compression dependencies. An uncached dependency is an offline build limitation;
do not silently drop that parser or claim its fuzz coverage.

With nightly and `cargo-fuzz` already available, run from the repository root:

```sh
cargo +nightly fuzz run research_detectors -- \
  -max_len=65536 -max_total_time=60 -timeout=5 \
  -rss_limit_mb=1024 -malloc_limit_mb=128 -print_final_stats=1
```

Supply an existing approved/synthetic corpus directory after the target name if
needed. The target's selector format above supports structured seeds as well as
ordinary `.eml` bytes. The [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
describes the usual workflow; LLVM documents the
[libFuzzer resource controls and output](https://llvm.org/docs/LibFuzzer.html#options).
Compilation alone is not a fuzzing run. Inspect startup output for coverage
counters and PC tables, then retain the final run statistics and exit status.
Crash artifacts contain input bytes, so use an appropriate local corpus/artifact
location and report a minimal synthetic reproducer where possible.

## Local coverage-only fallback

On the development host used for this change, `cargo-fuzz`, rustup/nightly and
the Rust AddressSanitizer runtime were absent. The installed Homebrew Rust 1.98.0
(aarch64-apple-darwin, LLVM 22.1.8) did support the LLVM sanitizer-coverage pass.
The following builds a real libFuzzer binary with coverage counters, PC tables,
comparison tracing, debug assertions and overflow checks. It does **not** enable
AddressSanitizer, instrument native C/C++ dependencies or rebuild Rust's standard
library. No nightly tooling or sanitizer installation is implied.

```sh
export NOISEFENCE_FUZZ_WORKDIR="$(mktemp -d /tmp/noisefence-research-fuzz.XXXXXX)"
export CARGO_TARGET_DIR="$NOISEFENCE_FUZZ_WORKDIR/target"
export CARGO_BUILD_JOBS=4
export CARGO_PROFILE_DEV_OPT_LEVEL=1
export CARGO_PROFILE_DEV_DEBUG=1
export RUSTFLAGS='--cfg fuzzing -C debug-assertions=yes -C overflow-checks=yes -C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=4 -C llvm-args=-sanitizer-coverage-inline-8bit-counters -C llvm-args=-sanitizer-coverage-pc-table -C llvm-args=-sanitizer-coverage-trace-compares'
cargo build --offline --locked --manifest-path fuzz/Cargo.toml \
  --bin research_detectors --target aarch64-apple-darwin
```

Using an explicit target keeps these flags off host build scripts/proc macros.
The pass names are compiler-specific: a failed build is a tooling failure, not
a passed fuzz test. Prefer the normal nightly workflow for longer sanitizer runs.

Generate the same 34 synthetic seed types and dictionary used for the local run:

```sh
python3 - <<'PY'
from pathlib import Path
import base64, io, json, os, struct, zlib, zipfile
root=Path(os.environ['NOISEFENCE_FUZZ_WORKDIR'])
corpus=root/'corpus'
corpus.mkdir(exist_ok=True)
(root/'artifacts').mkdir(exist_ok=True)

def put(name, data, mode=None):
    data=(bytes([mode])+data) if mode is not None else data
    assert len(data)<=65536
    (corpus/name).write_bytes(data)

def mime(kind, data):
    return ('MIME-Version: 1.0\r\nContent-Type: '+kind+'\r\nContent-Transfer-Encoding: base64\r\n\r\n').encode()+base64.b64encode(data)

def chunk(kind, data):
    return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))

def png(w=1,h=1):
    header=struct.pack('>IIBBBBB',w,h,8,0,0,0,0)
    return b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',header)+chunk(b'IDAT',zlib.compress(b'\0'*(w+1)*h))+chunk(b'IEND',b'')

def pdf(objects):
    out=bytearray(b'%PDF-1.7\n'); offsets=[]
    for i,obj in enumerate(objects,1):
        offsets.append(len(out)); out+=f'{i} 0 obj\n'.encode()+obj+b'\nendobj\n'
    xref=len(out)
    out+=f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode()
    for offset in offsets: out+=f'{offset:010} 00000 n \n'.encode()
    out+=f'trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
    return bytes(out)

def objstream(data):
    compressed=zlib.compress(b'2 0 '+data)
    return f'<< /Type /ObjStm /N 1 /First 4 /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n'.encode()+compressed+b'\nendstream'

def cfb():
    header=bytearray(512)
    header[:8]=bytes.fromhex('d0cf11e0a1b11ae1')
    struct.pack_into('<HHHHH',header,24,0x3e,3,0xfffe,9,6)
    struct.pack_into('<IIIIIIIII',header,40,0,1,1,0,4096,0xfffffffe,0,0xfffffffe,0)
    struct.pack_into('<109I',header,76,0,*([0xffffffff]*108))
    fat=struct.pack('<128I',0xfffffffd,0xfffffffe,*([0xffffffff]*126))
    def entry(name,kind,child,start):
        e=bytearray(128); n=(name+'\0').encode('utf-16le'); e[:len(n)]=n
        struct.pack_into('<HBBIII',e,64,len(n),kind,1,0xffffffff,0xffffffff,child)
        struct.pack_into('<I',e,116,start)
        return e
    directory=entry('Root Entry',5,1,0xfffffffe)+entry('VBA',1,0xffffffff,0)+bytes(256)
    return bytes(header)+fat+directory

def zipped(entries):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,payload in entries:
            info=zipfile.ZipInfo(name,(2020,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(info,payload)
    return data.getvalue()

html=b'<a href="java&#x09;script:example()">urgent action required</a><img onerror="example()"><script>example()</script>'
put('html-active',html,1)
put('html-comments',b'<!-- <script>x</script> --><textarea><img onerror=x></textarea>',1)
put('html-b64',base64.b64encode(html),10)
put('html-qp',b'<a href=3D"java=\r\nscript:example()">urgent</a>',11)
put('plain-heuristics',b'urgent urgent urgent urgent urgent urgent verify your account mot de passe',0)
put('header-heuristics',b'From: urgent <sender@example.invalid>\r\nSubject: Action required\r\nReply-To: account@example.invalid\r\n\r\nverify your account immediately')
put('headers-invalid',b'Subject: one\r\nSubject: two\r\n\r\nbody')
put('raw-cap',b'X'*(64*1024))
put('html-node-limit',b'<b>'*3000,1)
put('mime-parts',b''.join(b'--fuzz\r\nContent-Type: text/html\r\n\r\n<script>x</script>\r\n' for _ in range(18))+b'--fuzz--\r\n',8)
put('mime-truncated',b'--fuzz\r\nContent-Type: text/plain\r\n\r\nbody',8)
put('nested-message',mime('message/rfc822',mime('text/html',html)),9)
put('png-valid',png(),3)
put('png-bomb',png(512,512),3)
put('png-polyglot',png()+b'<script>x</script>',3)
put('png-raw-mime',mime('image/png',png()))
put('jpeg-framing',bytes.fromhex('ffd8ffc0000b080001000201011100ffda0008010100003f0042ff00ffd9'),4)
put('gif',base64.b64decode('R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=='),5)
active=pdf([b'<< /Type /Catalog /Open#41ction << /S /Java#53cript /J#53 (example) >> >>'])
put('pdf-escaped',active,2)
put('pdf-raw-mime',mime('application/pdf',active))
put('pdf-object-stream',pdf([objstream(b'<< /JS (example) >>')]),2)
put('pdf-bomb',pdf([objstream(b' '*100000)]),2)
put('pdf-indirect-length',pdf([b'<< /Length 2 0 R >>\nstream\nx\nendstream',b'1']),2)
put('pdf-encrypted',pdf([b'<< /Encrypt 2 0 R >>']),2)
put('pdf-deep',pdf([b'['*20+b'1'+b']'*20]),2)
vba=cfb()
put('cfb-vba',vba,7)
attack=bytearray(vba);struct.pack_into('<I',attack,44,109);struct.pack_into('<109I',attack,76,*([0]*109))
put('cfb-fat-limit',bytes(attack),7)
types=b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>'
put('office-xml',zipped([('[Content_Types].xml',types)]),6)
put('office-vba',zipped([('[Content_Types].xml',types),('word/vbaProject.bin',vba)]),6)
put('office-zip-bomb',zipped([('[Content_Types].xml',types),('word/data',b'\0'*100000)]),6)
put('office-zip-count',zipped([('[Content_Types].xml',types)]+[(str(i),b'x') for i in range(18)]),6)
put('office-xxe',zipped([('[Content_Types].xml',b'<!DOCTYPE Types [<!ENTITY x SYSTEM "file:///nonexistent-fuzz-fixture">]><Types>&x;</Types>')]),6)
put('office-xml11',zipped([('[Content_Types].xml',b'<?xml version="1.1"?><Types/>')]),6)
put('office-raw-mime',mime('application/zip',zipped([('[Content_Types].xml',types)])))
words=['Content-Type:','Content-Transfer-Encoding:','base64','quoted-printable','multipart/mixed; boundary=fuzz','--fuzz','text/html','application/pdf','/Java#53cript','/JS','/ObjStm','/Length','/Filter','/FlateDecode','stream','endstream','endobj','%%EOF','VBA','[Content_Types].xml','macroEnabled','<script>','javascript:','onerror=','&#x6a;','</Types>']
(root/'detectors.dict').write_text('\n'.join(json.dumps(w) for w in words)+'\n')
print('synthetic seed files:',len(list(corpus.iterdir())))
PY
"$CARGO_TARGET_DIR/aarch64-apple-darwin/debug/research_detectors" \
  "$NOISEFENCE_FUZZ_WORKDIR/corpus" \
  -dict="$NOISEFENCE_FUZZ_WORKDIR/detectors.dict" \
  -artifact_prefix="$NOISEFENCE_FUZZ_WORKDIR/artifacts/" \
  -seed=9012026 -runs=200000 -max_total_time=60 -timeout=5 \
  -max_len=65536 -rss_limit_mb=1024 -malloc_limit_mb=128 \
  -print_final_stats=1
```

The seed set includes raw MIME, transfer encodings, nested/malformed multiparts,
header duplication, an exact 64 KiB input, HTML node limits, PNG/GIF/JPEG framing,
PDF escaped names and Flate object streams, compressed bombs, encryption markers,
Office XML/ZIP, CFB VBA storage and malicious FAT amplification. Runtime-generated
coverage corpus entries and artifacts are kept outside tracked source files.
