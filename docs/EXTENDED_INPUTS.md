# Extended assessment inputs

The default ONNX/sklearn + CSV/NPZ workflow is unchanged. New options use the same
authenticated, rate-limited, owner-scoped scan route. Conversion never supplies a
signature, bypasses a gate, or approves deployment.

## Offline classic PCAP

In Upload Model, select **Offline PCAP + labels**, upload the capture and a separate
label CSV, and supply matching metadata. Only classic PCAP 2.4 Ethernet captures
are supported, not pcapng. There is no live capture or TLS decryption. Fragments,
truncation, malformed packets and excessive resource demands fail explicitly.

Label CSV columns must be exactly:

```csv
src_ip,src_port,dst_ip,dst_port,protocol,label
10.0.0.1,12345,10.0.0.2,443,tcp,Benign-HTTPS
```

Every supported bidirectional flow needs an explicit declared class label. Reverse
directions normalize together. Endpoint order, not inferred client/server roles,
defines sent/received. Reused connections sharing a tuple aggregate over the whole
capture; no timeout splitting, extrapolation or missing-label inference occurs.

Metadata must declare one of these precise preprocessing contracts:

- `pcap_flow_v1`: input_type tabular, target_column label. expected_features must
  equal, in order, flow_duration, packet_count, avg_packet_size, bytes_sent,
  bytes_received, iat_mean, iat_std, flow_bytes_per_second. Duration is milliseconds,
  IAT values seconds and byte counts full IP datagram lengths. These semantics
  must match training; this is not a recreation of arbitrary CIC/Zeek/DoH schemas.
- `pcap_transport_bytes_v1`: input_type sequence, sequence_dtype int64,
  vocab_size 257, pad_id 0, explicit max_sequence_length. Transport payload bytes
  become byte+1 tokens in capture order, then zero padding. TCP retransmissions
  remain, directions concatenate, and no stream reassembly occurs. Overlength
  flows reject rather than truncate. The model must use this exact encoding.

Default limits include 200 MiB input, one million packets, 100,000 flows and 64 MiB
output. Packet, mapping and timestamp checks impose further limits. Failures do
not publish partial datasets. Reports record source/mapping hashes, schema, counts
and skipped packets without embedding raw addresses or payloads. Captures can
still contain sensitive information: restrict upload access and retention.

```bat
python -m core.pcap_ingestion --input capture.pcap --output evaluation.csv --labels labels.csv --schema metadata.json
python scripts\run_phase1_scan.py --model model.onnx --dataset capture.pcap --metadata metadata.json --requirements requirements.txt --flow-labels labels.csv --no-docx
```

## Optional ONNX GPU execution

CPU remains the default. The upload page and CLI expose cpu, auto and cuda.
Metadata also accepts execution_device and execution_fallback (`error` or `cpu`).
Auto prefers available CUDA and permits CPU session fallback. Explicit CUDA fails
when unavailable unless CPU session fallback is allowed. Unsupported graph nodes
may still execute on CPU even with CUDA configured. Reports distinguish configured
and registered providers from sampled node execution, and never promise strict
GPU-only execution. Profiling observes the first successful tabular inference or
isolated sequence batches, not every future run.
The top-level report execution evidence is explicitly scoped to classifier
evaluation. Other inference stages receive the same requested device policy,
but the classifier's sampled profiling is not proof of their execution placement.

GPU acceleration requires compatible NVIDIA hardware, CUDA, cuDNN and the optional
onnxruntime-gpu distribution. It does not improve model accuracy. Use a separate
GPU environment and requirements-gpu.txt instead of the CPU onnxruntime package;
do not install both distributions together. Hardware validation is separate from
provider-selection unit tests.

```bat
python scripts\run_phase1_scan.py --model model.onnx --dataset test.csv --metadata metadata.json --device auto --no-docx
```

## Restricted native weights

Accepted layouts are float32 PyTorch `.safetensors` for approved mlp/cnn1d models,
or Keras 3 `.weights.h5` for approved built-in Dense-only mlp models. This does not
accept unrestricted .pt, .pth, full .keras/.h5, custom layers or uploaded Python.
Hidden layers use ReLU; CNNs use valid convolutions/ReLU/global mean. Other
architectures, activations and preprocessing are not compatible.

```json
{"schema_version":1,"framework":"pytorch","architecture":"mlp",
 "model_name":"approved-mlp","input_type":"tabular","input_size":3,
 "hidden_sizes":[4],"output_size":2,"class_labels":["safe","other"],
 "expected_features":["feature_a","feature_b","feature_c"],"target_column":"label"}
```

PyTorch tensor names are layers.0.weight/bias, etc., with weights [out,in]. CNNs
also use convs.0.weight/bias, channels, kernel_sizes, sequence_length, input_size=1
and float32 evaluation NPZ [N,L]. Keras supports the standard Dense save_weights
layers/dense/vars layout only; optimizer state, links and custom objects reject.
Native CNNs cannot directly consume the int64 PCAP token schema. Native MLP PCAP
use requires the explicit pcap_flow_v1 contract and matching training features.

The application converts these weights to standard ONNX operators in a trusted
Docker image; it does not need to install PyTorch/TensorFlow on the main server.
The operator must provision docker/native-import.Dockerfile, publish/resolve its
immutable image digest, pre-load it, and set
`NATIVE_IMPORT_IMAGE=registry/image@sha256:<64 hex characters>`. User metadata
cannot select an image. The importer never automatically builds, pulls or falls
back to host decoding. Without Docker and this configured image it fails closed;
normal ONNX/sklearn scans continue to work.

Training/baseline dataset references are restricted to the authenticated owner's
uploads or explicitly approved shared fixture/processed datasets. Metadata cannot
select another account's files or arbitrary server paths.

The nonroot worker has no network, a read-only root, dropped capabilities,
no-new-privileges, bounded tmpfs, CPU/memory/PID/file-size limits and independent
deadlines. Inputs are read-only and only a dedicated output directory is writable.
Cleanup also stops the container after a CLI timeout. Containers reduce exposure,
not eliminate every host/kernel/runtime risk; maintain the worker host.

```bat
python scripts\import_native_model.py model.safetensors metadata.json converted-model
```

Upload Model and `/scan/phase1` invoke the same importer. Reports record framework,
source hash, converter and immutable image reference. Converted models remain
untrusted; package/sign the converted ONNX separately for release.

## Trained sequence development fixtures

The quick deterministic sequence_test_kit remains unchanged. For genuinely trained
synthetic four-class, 128-token CNN fixtures:

```bat
python -m pip install -r requirements-model-build.txt
python scripts\build_test_sequence_model.py --trained --output-dir data\trained_sequence_test_kit
```

The builder checks strong/weak discrimination, Torch/ONNX parity and saliency
peaking in the known motif. Synthetic fixture accuracy is not guaranteed real
traffic performance. PyTorch is development-only, not a mandatory runtime or CI
dependency.

## Trust, reporting and passwords

Failed Security Gates block deployment regardless of score. Unsigned artifacts
retain their existing assessment-score cap. JSON signatures cover execution and
input-provenance fields; changing either invalidates verification. The Reports
page and DOCX exports also expose this evidence.

New reports retain the measured, pre-cap assessment score separately from the
published Trust Score. The dashboard explains when unsigned provenance limits
the latter to 70; different models can have different measured scores despite
the same capped score. Older reports reconstruct this value only when their
stored weights and module evidence are sufficient and consistent.

Upload Model retains its activity log while navigating within the signed-in
session. A new analysis replaces that log; refreshing starts a new session view.
Completed reports and analysis traces remain in owner-scoped database snapshots
regardless of the temporary upload panel. Interrupted scans show only recorded
progress and are not presented as completed or silently resumed in the background.

New password hashes use versioned PBKDF2 with 600,000 rounds. Existing bcrypt and
legacy PBKDF2 hashes remain verifiable. No stored accounts are rewritten merely
by installing this update; Passlib is no longer initialized at startup.
