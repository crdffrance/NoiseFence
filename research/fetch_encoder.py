#!/usr/bin/env python3
"""Download pinned data-only encoder artifacts; never run repository code."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


def verified(path, record):
    if not path.is_file() or path.stat().st_size != record['size']:
        return False
    algorithm = hashlib.sha256() if record['sha256'] else hashlib.sha1()
    if not record['sha256']:
        algorithm.update(f"blob {record['size']}\0".encode())
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            algorithm.update(block)
    return algorithm.hexdigest() == (record['sha256'] or record['git_blob'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    lock = json.loads(Path(__file__).with_name('encoder.lock.json').read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    for record in lock['artifacts']:
        name = record['path']
        if Path(name).name != name or not name.endswith(('.json', '.safetensors', '.model', '.md')):
            raise ValueError('Unexpected encoder artifact')
        path = args.output / name
        if verified(path, record):
            print(name + ' verified', flush=True)
            continue
        url = f"https://huggingface.co/{lock['id']}/resolve/{lock['revision']}/{name}"
        temporary = path.with_suffix(path.suffix + '.download')
        size = 0
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open('wb') as stream:
            while block := response.read(1024 * 1024):
                size += len(block)
                if size > record['size']:
                    raise ValueError('Encoder artifact exceeds pinned size')
                stream.write(block)
        if not verified(temporary, record):
            raise ValueError('Encoder artifact digest mismatch')
        temporary.replace(path)
        print(name + ' downloaded and verified', flush=True)
    (args.output / 'source.json').write_text(json.dumps(lock, indent=2) + '\n')


if __name__ == '__main__':
    main()
