# Trained synthetic sequence fixtures

Freshly generated on 2026-10-19 using `scripts/build_test_sequence_model.py`
with `--trained --output-dir data/trained_sequence_test_kit` and default seed 1729.
These artifacts were trained afresh, not copied from the earlier temporary build.

## Build environment

- Executable: `C:\Users\glady\Mini project\.venv\Scripts\python.exe`
- Python: 3.13.12; PyTorch: 2.10.0+cpu; training device: CPU.
- For this process only, appended
  `C:\Users\glady\AppData\Local\Programs\Python\Python313\Lib\site-packages`
  to `sys.path` to use already-installed Torch. No dependencies were installed
  or changed in the project environment.

Equivalent Python entry point, run from the project root with the executable above:

```python
import runpy
import sys

sys.path.append(
    r"C:\Users\glady\AppData\Local\Programs\Python\Python313\Lib\site-packages"
)
sys.argv = [
    "build_test_sequence_model.py",
    "--trained",
    "--output-dir",
    "data/trained_sequence_test_kit",
]
runpy.run_path("scripts/build_test_sequence_model.py", run_name="__main__")
```

The generator refuses to replace existing fixtures. Use a fresh output directory
for subsequent regeneration.

## Contents and limitations

Each variant directory contains its named ONNX model, `train.npz`, `test.npz`,
and `metadata.json`. Metadata records seeds, architecture, training configuration,
metrics, an occlusion sample, and a repository-relative training dataset path. Run
scans from the project root. NPZ arrays are `X` (int64 tokens), `y` (Unicode
synthetic class labels), and `motif_start` (known planted motif offsets).

Both variants share 3072 training and 768 held-out test sequences of length 128
across four balanced synthetic classes. The strong CNN trains for 12 epochs;
the weak CNN trains for one epoch on 32 rows from the same data, with the same
initialization and optimizer. ONNX uses standard operators, opset 15, and embedded
weights with no external tensor data. Normal ONNX inference does not need Torch.

The generator checked PyTorch/ONNX logits parity and normalized probabilities.
Strong held-out accuracy and weighted F1 were 1.0; weak accuracy was
0.2447916667 and weighted F1 was 0.1852612983. Strong single-token occlusion
peaked at position 85, inside the known motif at positions 84 through 87.

The real project `evaluate_classifier` backend was then run against both permanent
ONNX/test-NPZ pairs using their metadata, without the Torch import-path addition.
Strong returned `pass`, score 100.00, accuracy 1.0, weighted F1 1.0. Weak returned
the expected `fail`, score 18.53, accuracy 0.2448, weighted F1 0.1853.
Both passed `validate_onnx_model` safety checks with input shape `[None, 128]`.
No full test suite was run for this bounded artifact build.

These sequences are artificial ordered token motifs with random background,
not network captures. Scores do not establish real traffic detection, privacy,
or robustness. Reproduction assumes the same dependency environment; identical
seeds do not guarantee bitwise identity across dependency versions.

The existing `data/sequence_test_kit` and the generator were not modified by
this permanent artifact build.
