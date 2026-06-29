#!/usr/bin/env python3
"""Convert .pt encoder weights to .npz for torch-free inference in the container."""
import numpy as np
from pathlib import Path

try:
    import torch
except ImportError:
    raise SystemExit("torch needed locally: pip install torch --index-url https://download.pytorch.org/whl/cpu")

models_dir = Path(__file__).parent / 'models'
for ds in ['darknet', 'ids2018', 'unsw']:
    pt_path = models_dir / ds / 'encoder_weights.pt'
    npz_path = models_dir / ds / 'encoder_weights.npz'
    if not pt_path.exists():
        print(f"[{ds}] encoder_weights.pt missing — skipping")
        continue
    raw = torch.load(str(pt_path), map_location='cpu', weights_only=True)
    if any(k.startswith('encoder.') for k in raw):
        raw = {k[len('encoder.'):]: v for k, v in raw.items() if k.startswith('encoder.')}
    np_weights = {k.replace('.', '__'): v.numpy() for k, v in raw.items()}
    np.savez(str(npz_path), **np_weights)
    print(f"[{ds}] {len(np_weights)} arrays → {npz_path}")

print("Done.")
