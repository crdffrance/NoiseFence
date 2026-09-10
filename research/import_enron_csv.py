#!/usr/bin/env python3
"""Import an Enron CSV ZIP offline, with provenance and labels outside MIME."""
import argparse
from collections import Counter
import csv
from email.message import EmailMessage
from email.policy import SMTP
import hashlib
import io
import json
from pathlib import Path
import os
import shutil
import tempfile
import zipfile

MAX_ARCHIVE = 100 * 1024 * 1024
MAX_MESSAGE = 2 * 1024 * 1024
COLUMNS = ['Message ID', 'Subject', 'Message', 'Spam/Ham', 'Date']


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def import_archive(archive, output):
    archive, output = Path(archive), Path(output)
    if output.exists():
        raise ValueError('Output must be a new directory')
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError('Archive exceeds size limit')
    archive_bytes = archive.read_bytes()
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zipped:
        members = zipped.infolist()
        if (len(members) != 1 or members[0].filename != 'enron_spam_data.csv'
                or members[0].is_dir() or members[0].flag_bits & 1
                or members[0].file_size > MAX_ARCHIVE):
            raise ValueError('Expected a single bounded, unencrypted enron_spam_data.csv')
        # Never extract archive paths, attributes, links or executable permissions.
        with zipped.open(members[0]) as stream:
            data = stream.read(MAX_ARCHIVE + 1)
        if len(data) > MAX_ARCHIVE:
            raise ValueError('Expanded archive exceeds size limit')
    csv.field_size_limit(MAX_MESSAGE)
    reader = csv.DictReader(io.StringIO(data.decode('utf-8-sig'), newline=''), strict=True)
    if reader.fieldnames != COLUMNS:
        raise ValueError('Unexpected CSV columns')
    rows, labels, counts, years = {}, Counter(), Counter(), Counter()
    for record in reader:
        counts['input_rows'] += 1
        if counts['input_rows'] > 100_000:
            raise ValueError('Too many CSV records')
        if set(record) != set(COLUMNS) or any(v is None for v in record.values()):
            raise ValueError('Invalid CSV record')
        label = record['Spam/Ham'].strip().lower()
        if label not in ('ham', 'spam'):
            raise ValueError('Unknown label; no candidate imported')
        labels[label] += 1
        subject, body = record['Subject'], record['Message']
        counts['removed_nul_bytes'] += subject.count('\0') + body.count('\0')
        subject = ' '.join(subject.replace('\0', '').split())
        body = body.replace('\0', '').replace('\r\n', '\n').replace('\r', '\n')
        if not subject and not body.strip():
            counts['empty_messages_removed'] += 1
            continue
        if len((subject + body).encode('utf-8')) > MAX_MESSAGE:
            counts['oversized_messages_removed'] += 1
            continue
        year = record['Date'][:4]
        year = int(year) if len(year) == 4 and year.isascii() and year.isdigit() else None
        years[str(year)] += 1
        key = sha256(json.dumps([subject, body], ensure_ascii=False).encode('utf-8'))
        if key not in rows:
            rows[key] = [subject, body, set(), 0, year]
        rows[key][2].add(label)
        rows[key][3] += 1
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.enron-import-', dir=output.parent))
    try:
        (stage / 'messages').mkdir(mode=0o700)
        with (stage / 'manifest.jsonl').open('w', encoding='utf-8') as manifest:
            for key in sorted(rows):
                subject, body, assigned, copies, year = rows[key]
                if len(assigned) != 1:
                    counts['conflicting_exact_groups_removed'] += 1
                    counts['conflicting_exact_rows_removed'] += copies
                    continue
                counts['exact_duplicate_rows_removed'] += copies - 1
                message = EmailMessage(policy=SMTP)
                if subject:
                    message['Subject'] = subject
                message.set_content(body, charset='utf-8', cte='8bit')
                raw = message.as_bytes()
                if len(raw) > MAX_MESSAGE:
                    counts['oversized_mime_removed'] += 1
                    continue
                relative = 'messages/' + sha256(raw) + '.eml'
                (stage / relative).write_bytes(raw)
                label = next(iter(assigned))
                manifest.write(json.dumps({'path': relative, 'spam': label == 'spam',
                    'source': 'enron-csv-20260910', 'year': year,
                    'external_test': False}) + '\n')
                counts['exported'] += 1
                counts['exported_' + label] += 1
        report = {'schema': 'noisefence-enron-csv-import-1',
            'archive_sha256': sha256(archive_bytes), 'csv_sha256': sha256(data),
            'input_labels': labels, 'counts': counts, 'source_date_years': years,
            'mime_fields': ['Subject', 'MIME-Version', 'Content-Type', 'Content-Transfer-Encoding', 'body'],
            'excluded_from_features': ['Message ID', 'Spam/Ham', 'Date', 'source', 'path'],
            'normalization': 'Remove NUL; unfold subject; normalize line endings; UTF-8 text/plain. No invented identities or dates.',
            'limitations': ['User-supplied historical binary labels, not reviewed consent or phishing labels.',
                'CSV does not preserve original SMTP/MIME context.',
                'Source dates are not trusted reception dates; redistribution rights not established.',
                'Canonical/near-duplicate grouping and cross-corpus audit still required.']}
        (stage / 'import.json').write_text(json.dumps(report, indent=2) + '\n')
        # umask also applies when this function is used outside the CLI.
        for p in stage.rglob('*'):
            p.chmod(0o700 if p.is_dir() else 0o600)
        stage.rename(output)
        return report
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    print(json.dumps(import_archive(args.archive, args.output), indent=2))


if __name__ == '__main__':
    main()
