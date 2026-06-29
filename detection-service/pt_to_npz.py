#!/usr/bin/env python3
"""
Convert PyTorch .pt state-dict files to .npz without requiring torch.

PyTorch saves state dicts as zip archives containing a pickle file that
references raw binary storage blobs. This script monkey-patches the
unpickler so tensor references resolve to numpy arrays instead.

Usage:
    python pt_to_npz.py models/darknet/encoder_weights.pt
    # writes models/darknet/encoder_weights.npz
"""

import io
import pickle
import struct
import sys
import zipfile
from pathlib import Path

import numpy as np

# ── dtype map ─────────────────────────────────────────────────────────────────
# PyTorch storage type name → (numpy dtype, element size in bytes)
STORAGE_TYPES = {
    "FloatStorage":  (np.float32, 4),
    "DoubleStorage": (np.float64, 8),
    "HalfStorage":   (np.float16, 2),
    "LongStorage":   (np.int64,   8),
    "IntStorage":    (np.int32,   4),
    "ShortStorage":  (np.int16,   2),
    "ByteStorage":   (np.uint8,   1),
    "BoolStorage":   (np.bool_,   1),
}


class _FakeStorage:
    """Stands in for a torch.*Storage object during unpickling."""
    def __init__(self, data: np.ndarray):
        self.data = data


class _FakeModule:
    """Minimal fake torch / torch.storage module for the unpickler."""
    def __init__(self, storage_map):
        self._smap = storage_map

    def __getattr__(self, name):
        if name in self._smap:
            dtype, itemsize = self._smap[name]
            def make_storage(size):
                return _FakeStorage(np.zeros(size, dtype=dtype))
            return make_storage
        return lambda *a, **kw: None


def _rebuild_tensor_v2(storage, offset, size, stride, *args):
    """Replacement for torch._utils._rebuild_tensor_v2."""
    arr = storage.data
    total = 1
    for s in size:
        total *= s
    # Slice and reshape
    flat = arr[offset: offset + total]
    if len(size) == 0:
        return flat.reshape(())
    return flat.reshape(size)


def _rebuild_from_type_v2(func, new_type, args, state):
    return func(*args)


class _TorchUnpickler(pickle.Unpickler):
    """Custom unpickler that replaces torch classes with numpy equivalents."""

    def __init__(self, file, zip_file, prefix="archive/"):
        super().__init__(file)
        self._zip    = zip_file
        self._prefix = prefix

    def find_class(self, module, name):
        # torch._utils._rebuild_tensor_v2 → our numpy version
        if name == "_rebuild_tensor_v2":
            return _rebuild_tensor_v2
        if name == "_rebuild_from_type_v2":
            return _rebuild_from_type_v2
        if name == "_rebuild_tensor":
            return _rebuild_tensor_v2
        # Storage constructors
        if module in ("torch", "torch.storage", "_codecs") and name in STORAGE_TYPES:
            dtype, itemsize = STORAGE_TYPES[name]
            def make(size, dtype=dtype):
                return _FakeStorage(np.zeros(size, dtype=dtype))
            return make
        # Persistent load is handled by persistent_load below
        return super().find_class(module, name)

    def persistent_load(self, pid):
        """Load a tensor storage from the zip archive."""
        # pid format: ('storage', storage_type, key, location, size)
        type_tag, dtype_class, key, location, size = pid
        dtype, itemsize = STORAGE_TYPES.get(dtype_class.__name__,
                                             STORAGE_TYPES.get(dtype_class, (np.float32, 4)))
        # Read raw bytes from <prefix>data/<key>
        try:
            raw = self._zip.read(f"{self._prefix}data/{key}")
        except KeyError:
            raw = self._zip.read(f"{self._prefix}{key}")
        arr = np.frombuffer(raw, dtype=dtype).copy()
        return _FakeStorage(arr)


def load_pt(pt_path: Path) -> dict:
    """Load a .pt state dict as a plain dict of numpy arrays."""
    with zipfile.ZipFile(str(pt_path)) as zf:
        # Detect root prefix — may be 'archive/' or '<model_name>/'
        names = zf.namelist()
        prefix = names[0].split("/")[0] + "/"
        with zf.open(f"{prefix}data.pkl") as pkl_f:
            unpickler = _TorchUnpickler(pkl_f, zf, prefix)
            state_dict = unpickler.load()
    # Flatten: extract .data from any _FakeStorage that leaked through
    result = {}
    for k, v in state_dict.items():
        if isinstance(v, _FakeStorage):
            result[k] = v.data
        elif isinstance(v, np.ndarray):
            result[k] = v
        else:
            result[k] = np.array(v)
    return result


def convert(pt_path: Path) -> Path:
    print(f"Loading {pt_path.name} ...")
    sd = load_pt(pt_path)

    # Remap encoder.net.* → net.* if saved as full ETSSLModel
    if any(k.startswith("encoder.") for k in sd):
        sd = {k[len("encoder."):]: v for k, v in sd.items()
              if k.startswith("encoder.")}

    # Save with '.' → '__' for npz key safety
    np_weights = {k.replace(".", "__"): v.astype(np.float32) for k, v in sd.items()}
    out = pt_path.with_suffix(".npz")
    np.savez(str(out), **np_weights)

    print(f"  {len(np_weights)} arrays → {out.name}")
    for k, v in sorted(np_weights.items()):
        print(f"    {k:<40} {v.shape}")
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Convert all three models
        base = Path(__file__).parent / "models"
        pts  = list(base.glob("*/encoder_weights.pt"))
        if not pts:
            sys.exit("No encoder_weights.pt files found under models/")
    else:
        pts = [Path(p) for p in sys.argv[1:]]

    for pt in pts:
        convert(pt)
    print("\nDone — you can now build the detection-service container.")
