#!/usr/bin/env python3
"""Frozen local encoder comparison, without sending email content to a service."""
import argparse
import json
import os
from pathlib import Path
import time

import numpy as np
import torch
import transformers
from transformers import AutoModel, AutoTokenizer
from fetch_encoder import verified
from train_linear import digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('texts', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--encoder', type=Path, required=True)
    p.add_argument('--device', choices=('cpu', 'mps'), default='cpu')
    p.add_argument('--batch-size', type=int, default=16)
    p.add_argument('--max-tokens', type=int, default=256)
    a = p.parse_args()
    os.umask(0o077)
    if not 1 <= a.batch_size <= 64 or not 32 <= a.max_tokens <= 512:
        raise ValueError('Invalid resource bounds')
    lock = json.loads(Path(__file__).with_name('encoder.lock.json').read_text())
    if not all(verified(a.encoder / row['path'], row) for row in lock['artifacts']):
        raise ValueError('Encoder artifacts differ from lock file')
    if a.device == 'mps' and not torch.backends.mps.is_available():
        raise RuntimeError('MPS is unavailable; use --device cpu explicitly')
    torch.set_num_threads(4)
    torch.manual_seed(20260907)
    tokenizer = AutoTokenizer.from_pretrained(a.encoder, local_files_only=True, trust_remote_code=False)
    model = AutoModel.from_pretrained(a.encoder, local_files_only=True,
                                      trust_remote_code=False, use_safetensors=True)
    model.eval().to(a.device)
    ids = []
    with a.texts.open() as source:
        for line in source:
            row = json.loads(line)
            if row['text_schema'] != 3:
                raise ValueError('Unexpected text extraction schema')
            ids.append(row['raw_sha256'])
    if len(set(ids)) != len(ids):
        raise ValueError('Repeated raw messages')
    a.output.mkdir(parents=True, exist_ok=False)
    protocol = {'encoder': lock['id'], 'revision': lock['revision'],
                'texts_sha256': digest(a.texts), 'text_schema': 3,
                'rows': len(ids), 'dimensions': model.config.hidden_size,
                'prefix': 'query: ', 'max_tokens': a.max_tokens,
                'pooling': 'attention-mask mean then L2', 'device': a.device,
                'weights_frozen': True, 'test_evaluated': False,
                'batch_size': a.batch_size, 'torch': torch.__version__,
                'transformers': transformers.__version__}
    (a.output / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n')
    (a.output / 'ids.json').write_text(json.dumps(ids) + '\n')
    output = np.lib.format.open_memmap(a.output / 'embeddings.npy', mode='w+',
                                      dtype=np.float32, shape=(len(ids), model.config.hidden_size))
    count, batch, timings = 0, [], []

    def encode():
        nonlocal count, batch
        start = time.monotonic()
        inputs = tokenizer(batch, max_length=a.max_tokens, padding=True, truncation=True, return_tensors='pt')
        inputs = {key: value.to(a.device) for key, value in inputs.items()}
        with torch.inference_mode():
            hidden = model(**inputs).last_hidden_state
            mask = inputs['attention_mask'].unsqueeze(-1).bool()
            pooled = hidden.masked_fill(~mask, 0.0).sum(dim=1) / mask.sum(dim=1)
            vector = torch.nn.functional.normalize(pooled, p=2, dim=1).cpu().numpy()
        if not np.isfinite(vector).all():
            raise ValueError('Non-finite encoder result')
        output[count:count + len(batch)] = vector
        count += len(batch)
        timings.append(time.monotonic() - start)
        batch = []
        if count % 512 == 0:
            output.flush()
            print(json.dumps({'encoded': count, 'total': len(ids),
                              'seconds': round(sum(timings), 2)}), flush=True)

    with a.texts.open() as source:
        for line in source:
            row = json.loads(line)
            batch.append('query: ' + row['subject'] + '\n' + row['body'])
            if len(batch) == a.batch_size:
                encode()
    if batch:
        encode()
    output.flush()
    protocol.update({'complete': True, 'encoded': count,
                     'elapsed_inference_seconds': sum(timings),
                     'batch_p95_ms': float(np.percentile(timings, 95) * 1000),
                     'embeddings_sha256': digest(a.output / 'embeddings.npy')})
    (a.output / 'protocol.json').write_text(json.dumps(protocol, indent=2) + '\n')
    print(json.dumps(protocol, indent=2))


if __name__ == '__main__':
    main()
