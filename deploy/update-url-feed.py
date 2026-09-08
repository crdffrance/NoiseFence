#!/usr/bin/env python3
"""Import a licensed HTTPS/plain-text URL feed into the local NoiseFence matcher."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request
import urllib.parse

LIMIT = 8 * 1024 * 1024
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Feed redirects are disabled')

def convert(data, now=None):
    if len(data) > LIMIT:
        raise ValueError('Feed exceeds 8 MiB')
    urls = set()
    for line in data.decode('utf-8-sig').splitlines():
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        if len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise ValueError('Malformed URL in feed')
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Feed must contain one HTTP(S) URL per line')
        urls.add(value)
        if len(urls) > 50000:
            raise ValueError('Feed exceeds 50000 URLs')
    if not urls:
        raise ValueError('Empty feed refused; previous data preserved')
    result = json.dumps({'version':1, 'updated':int(time.time() if now is None else now), 'urls':sorted(urls)}, ensure_ascii=False).encode()
    if len(result) > LIMIT:
        raise ValueError('Encoded feed exceeds 8 MiB')
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path('/var/lib/noisefence'))
    p.add_argument('--input',type=Path,help='Import an existing licensed feed without network access')
    args = p.parse_args()
    if args.input:
        with args.input.open('rb') as source:
            data = source.read(LIMIT + 1)
    else:
        address = os.environ.get('NOISEFENCE_PHISHING_FEED_URL', '')
        if not address:
            raise SystemExit('No licensed feed configured; set NOISEFENCE_PHISHING_FEED_URL')
        if urllib.parse.urlsplit(address).scheme != 'https':
            raise SystemExit('HTTPS is required for feed download')
        client = urllib.request.build_opener(NoRedirect())
        try:
            with client.open(urllib.request.Request(address,headers={'User-Agent':'NoiseFence/feed-updater'}),timeout=20) as response:
                data = response.read(LIMIT + 1)
        except Exception:
            raise SystemExit('Feed download failed; previous data preserved') from None
    encoded = convert(data)
    directory = args.root / 'protection'
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.url-feed-',dir=directory)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(encoded)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary,directory/'url-feed.json')
        fd = os.open(directory,os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(json.dumps({'updated':True,'urls':len(json.loads(encoded)['urls'])}))
if __name__ == '__main__':
    main()
