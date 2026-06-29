import numpy as np
import sys

for ds in ['darknet', 'ids2018', 'unsw']:
    path = f'/home/millie/Sentinel/detection-service/models/{ds}/encoder_weights.npz'
    d = np.load(path)
    keys = list(d.files)
    print(f"\n{ds}: {len(keys)} arrays")
    print(f"  keys: {keys[:8]}")
    bn_var_keys = [k for k in keys if 'running_var' in k]
    for k in bn_var_keys:
        v = d[k]
        print(f"  {k}: min={v.min():.6f} max={v.max():.6f} mean={v.mean():.6f}")
    lin_w_keys = [k for k in keys if k.endswith('weight') and 'running' not in k]
    for k in lin_w_keys[:2]:
        w = d[k]
        print(f"  {k}: shape={w.shape}")
