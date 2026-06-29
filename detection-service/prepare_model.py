#!/usr/bin/env python3
"""
Prepare trained ET-SSL artifacts for the detection service.

Downloads real model files from HF Hub (local repo has LFS pointers),
transforms them into the format detector.py expects, and writes them into
detection-service/models/<dataset>/.

Requires only: huggingface_hub, joblib, numpy  (no torch needed here —
key remapping of the .pt file is handled at load-time in detector.py).

Install deps:
    pip install huggingface_hub joblib numpy

Usage:
    python prepare_model.py                   # all three models
    python prepare_model.py --dataset unsw
    HF_TOKEN=hf_xxx python prepare_model.py
"""

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import joblib
import numpy as np

# TrafficScaler lives in hybrid-detection/model/preprocessor.py.
# joblib needs it importable to deserialize the saved scaler.
_HYBRID = Path(__file__).parent.parent / 'hybrid-detection'
if str(_HYBRID) not in sys.path:
    sys.path.insert(0, str(_HYBRID))

HUB_REPO   = os.getenv('HF_MODEL_REPO', 'milliemuro/Sentinel')
MODELS_DIR = Path(__file__).parent / 'models'


def _download(filename: str, dest_dir: Path, token) -> Path:
    from huggingface_hub import hf_hub_download
    print(f"  Downloading {filename} ...")
    path = hf_hub_download(
        repo_id=HUB_REPO,
        filename=filename,
        repo_type='model',
        token=token,
        local_dir=str(dest_dir),
        local_dir_use_symlinks=False,
    )
    return Path(path)


def prepare(dataset: str, token) -> None:
    out_dir = MODELS_DIR / dataset
    print(f"\nPreparing {dataset}  →  {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # ── Download from HF Hub ──────────────────────────────────────────────
        try:
            meta_path     = _download(f'meta_{dataset}.json',     tmp, token)
            enc_path      = _download(f'encoder_{dataset}.pt',    tmp, token)
            scaler_path   = _download(f'scaler_{dataset}.joblib', tmp, token)
            centroid_path = _download(f'centroid_{dataset}.npy',  tmp, token)
        except Exception as e:
            print(f"  ERROR downloading {dataset}: {e}")
            return

        # ── 1. Flatten meta → model_meta.json ────────────────────────────────
        with open(meta_path) as f:
            meta = json.load(f)

        cfg      = meta['best_config']
        n_hidden = cfg.get('n_hidden', 3)
        if n_hidden == 2:
            hidden_dims = [cfg['hidden_w1'], cfg['hidden_w2']]
        elif n_hidden == 3:
            hidden_dims = [cfg['hidden_w1'], cfg['hidden_w2'], cfg['hidden_w3']]
        else:
            hidden_dims = [cfg['hidden_w1'], cfg['hidden_w2'],
                           cfg['hidden_w3'], cfg['hidden_w4']]

        threshold = meta.get('threshold') or 0.0
        if threshold == 0.0:
            print("  WARNING: no calibrated threshold — set ANOMALY_THRESHOLD in docker-compose")

        model_meta = {
            'feature_dim': 20,
            'embed_dim':   meta['embed_dim'],
            'dropout':     cfg.get('dropout', 0.3),
            'threshold':   float(threshold),
            'hidden_dims': hidden_dims,
            'dataset':     dataset,
            'val_auc':     meta.get('val_auc'),
            'test_auc':    meta.get('test_auc'),
        }
        with open(out_dir / 'model_meta.json', 'w') as f:
            json.dump(model_meta, f, indent=2)
        print(f"  model_meta.json   threshold={threshold:.4f}  hidden={hidden_dims}")

        # ── 2. Export encoder weights as .npz (no torch needed in container) ──
        # torch is only required locally here to load the .pt file.
        try:
            import torch
        except ImportError:
            sys.exit("torch is required locally to convert weights. "
                     "Run: pip install torch --index-url https://download.pytorch.org/whl/cpu")

        raw = torch.load(str(enc_path), map_location='cpu')
        # Remap full model keys: encoder.net.* → net.*
        if any(k.startswith('encoder.') for k in raw):
            raw = {k[len('encoder.'):]: v for k, v in raw.items()
                   if k.startswith('encoder.')}
        # Save each tensor as numpy; replace '.' with '__' for npz key safety
        np_weights = {k.replace('.', '__'): v.numpy() for k, v in raw.items()}
        np.savez(str(out_dir / 'encoder_weights.npz'), **np_weights)
        print(f"  encoder_weights.npz  ({len(np_weights)} arrays, no torch needed in container)")

        # ── 3. Extract raw RobustScaler from TrafficScaler wrapper ────────────
        traffic_scaler = joblib.load(scaler_path)
        raw_scaler = getattr(traffic_scaler, '_scaler', traffic_scaler)
        joblib.dump(raw_scaler, out_dir / 'scaler.joblib')
        print(f"  scaler.joblib  ({type(raw_scaler).__name__})")

        # ── 4. Copy centroid ──────────────────────────────────────────────────
        centroid = np.load(centroid_path).astype(np.float32)
        np.save(out_dir / 'centroid.npy', centroid)
        print(f"  centroid.npy  shape={centroid.shape}")

    print(f"  Done → {out_dir}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', default='all',
                    choices=['darknet', 'ids2018', 'unsw', 'all'])
    ap.add_argument('--token', default=os.getenv('HF_TOKEN'))
    args = ap.parse_args()

    if not args.token:
        print("Warning: HF_TOKEN not set — will fail on private repos.")

    datasets = ['darknet', 'ids2018', 'unsw'] if args.dataset == 'all' else [args.dataset]
    for ds in datasets:
        prepare(ds, args.token)

    print("\nAll done. Restart the detection-service container:")
    print("  docker compose up --build detection-service")


if __name__ == '__main__':
    main()
