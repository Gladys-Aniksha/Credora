# Extended assessment inputs

The default ONNX/sklearn + CSV/NPZ workflow is unchanged. Extended inputs use the same
authenticated, rate-limited, owner-scoped scan route. Conversion never supplies a
signature, bypasses a gate, or approves deployment.

The supported paths are ONNX tabular/sequence models, secured sklearn artifacts
and signed model packages, with optional ONNX GPU selection and bounded labeled
classic-PCAP conversion. Framework checkpoint/weights files are not accepted;
export a compatible model to ONNX before upload. The API and dashboard run as
Python processes with no external model-conversion service.

## Runtime dependencies

- Standard deployment uses `requirements.txt`, including CPU `onnxruntime`.
  Ordinary ONNX/sklearn scans do not require any optional requirements file.
- `requirements-gpu.txt` supplies the alternative `onnxruntime-gpu` distribution
  for a dedicated NVIDIA environment. Keep the other application dependencies,
  but exclude CPU `onnxruntime`; never install both distributions together. This
  file is not a supplement to an unchanged CPU-runtime installation.
- Framework exporters and optional fixture-training Torch belong in separate
  development/export environments. They are not application server dependencies;
  the default quick fixture builder does not require Torch.
- Classic-PCAP parsing needs no additional parser package. It uses the Python
  standard library and imports NumPy only for NPZ sequence output.

## Offline classic PCAP

In Upload Model, select **Offline PCAP + labels**, upload the capture and a separate
label CSV, and supply matching metadata. The exact capture contract is:

- Classic PCAP version 2.4, either endian order, with microsecond or nanosecond
  timestamp resolution. Ethernet linktype 1 without extra linktype flags only;
  at most two 802.1Q/802.1ad VLAN tags.
- IPv4/IPv6 TCP or UDP. IPv6 hop-by-hop, routing, destination-option and AH header
  chains are supported only within the bound of eight headers.
- IPv4 fragments/reserved fragmentation flag, all IPv6 fragments (even atomic
  fragments), ESP in either IP version, jumbograms and pcapng are rejected.
  IPv4 ESP fails explicitly rather than counting as a skipped non-TCP/UDP packet;
  IPv6 ESP is also rejected after supported extension headers.
- Truncated global/record/packet headers or bodies, malformed lengths,
  snaplen-truncated records and decreasing timestamps across the entire capture
  fail conversion. Captured and original record lengths must match; timestamp
  fractions must fit the declared resolution. Equal timestamps are allowed.
- Non-IP Ethernet frames and other IP protocols are skipped and counted. The
  capture must contain at least one supported, explicitly labeled TCP/UDP flow.

There is no live capture, TLS decryption, TCP stream reassembly or checksum
validation. Payload is copied as captured; encrypted bytes remain encrypted.

Label CSV columns must be exactly:

```csv
src_ip,src_port,dst_ip,dst_port,protocol,label
10.0.0.1,12345,10.0.0.2,443,tcp,Benign-HTTPS
```

Every supported bidirectional flow needs an explicit label in metadata's
`class_labels`. The protocol column accepts `tcp`/`udp` or `6`/`17`. Reverse keys
normalize identically; duplicates, including reversed duplicates, are errors.
Unused label mappings are allowed, but a mapping that labels none of the actual
supported flows cannot satisfy the per-flow requirement.

Endpoint order is `(IP version, packed IP address, port)`, not inferred
client/server roles; endpoint A to B defines sent bytes. Reused connections
sharing a tuple aggregate over the whole capture, with no timeout splitting,
extrapolation or missing-label inference. Output rows sort by `(protocol, A, B)`;
the converter's `flow_keys` records this order.

Metadata must declare one of these precise preprocessing contracts:

- `pcap_flow_v1`: input_type tabular, target_column label. expected_features must
  equal, in order, flow_duration, packet_count, avg_packet_size, bytes_sent,
  bytes_received, iat_mean, iat_std, flow_bytes_per_second. Duration is milliseconds,
  IAT values seconds and byte counts full IP datagram lengths (including IP and
  transport headers, excluding Ethernet, padding and FCS). `packet_count` counts
  captured IP packets, `avg_packet_size` is total IP bytes / count, and IAT standard
  deviation is the population statistic of successive flow gaps (zero with one
  packet). Rate is total IP bytes / observed duration, or zero for zero duration.
  CSV columns are exactly these eight features followed by `label`. These
  semantics must match training; this is not arbitrary CIC/Zeek/DoH compatibility.
- `pcap_transport_bytes_v1`: input_type sequence, sequence_dtype int64,
  vocab_size 257, pad_id 0, explicit max_sequence_length from 1 through 8192.
  `target_column` must be `label`; tabular `expected_features` must be absent.
  NPZ contains only `X:int64[flows,length]` and `y:unicode[flows]`. Transport payload bytes
  become byte+1 tokens in capture order, then zero padding. TCP retransmissions
  remain, directions concatenate, and no stream reassembly occurs. Overlength
  flows reject rather than truncate. The model must use this exact encoding.

Both schemas require an explicit `target_column: "label"` and nonempty unique
`class_labels`. Default converter limits are 200 MiB capture input, one million
packet records, 100,000 flows, 256 KiB per packet/snaplen, 8 MiB label CSV,
100,000 label rows and 64 MiB output/dense arrays. The CLI exposes every `Limits`
field as a `--max-...` flag. Application upload/NPZ limits are separate; passing
conversion limits does not override downstream limits.

Limits fail the whole conversion. Only one packet, flow aggregates and bounded
sequence tokens are retained, and output is atomically replaced after successful
validation; failed conversion does not publish a partial dataset. Reports record
source/mapping hashes, schema, counts and skipped packets without embedding raw
addresses or payloads. Captures can
still contain sensitive information: restrict upload access and retention.

Why this narrow format: explicit byte/packet/flow/header limits bound hostile
input processing, and fixed feature contracts make training/evaluation semantics
auditable. Fragment reassembly, ESP decoding, guessed labels and arbitrary exporter
schemas would add ambiguity and parsing cost that this converter does not support.

```bat
python -m core.pcap_ingestion --input capture.pcap --output evaluation.csv --labels labels.csv --schema metadata.json
python scripts\run_phase1_scan.py --model model.onnx --dataset capture.pcap --metadata metadata.json --requirements requirements.txt --flow-labels labels.csv --no-docx
```

## Optional ONNX GPU execution

CPU remains the default. The upload page and CLI expose cpu, auto and cuda.
Metadata also accepts `execution_device` and `execution_fallback` (`error` or `cpu`).
Auto prefers available CUDA and permits CPU session fallback by default; explicit
`execution_fallback: "error"` disallows that fallback. Explicit CUDA fails
when unavailable unless CPU session fallback is allowed. Unsupported graph nodes
may still execute on CPU even with CUDA configured. Reports distinguish configured
and registered providers from sampled node execution, and never promise strict
GPU-only execution: `strict_gpu_guarantee` is always `False` (JSON `false`).
Profiling observes the first successful tabular inference or
isolated sequence batches, not every future run.
The top-level report execution evidence is explicitly scoped to classifier
evaluation. Other inference stages receive the same requested device policy,
but the classifier's sampled profiling is not proof of their execution placement.

GPU acceleration requires compatible NVIDIA hardware, CUDA, cuDNN and the optional
onnxruntime-gpu distribution. It does not improve model accuracy. Use a separate
GPU environment and requirements-gpu.txt instead of the CPU onnxruntime package;
do not install both distributions together. Hardware validation is separate from
provider-selection unit tests.

Why opt-in: CPU deployments remain predictable without GPU packages or compatible
drivers, while CUDA availability and graph support differ by runtime and model.
CUDA registration is not node-placement evidence. Successful GPU hardware execution
has not been verified in this environment; mocked provider tests and real CPU
fallback checks do not establish GPU correctness or speedup.

```bat
python scripts\run_phase1_scan.py --model model.onnx --dataset test.csv --metadata metadata.json --device auto --no-docx
```

## ONNX export compatibility

Export framework models on the model owner's machine in a separate development
environment, then upload only the compatible ONNX artifact, evaluation dataset
and metadata. Credora does not decode framework checkpoints or execute uploaded
Python. See the [README export examples](../README.md#bring-your-own-onnx-export)
for PyTorch, TensorFlow/Keras and scikit-learn.

An export must fit the deployed ONNX Runtime's supported operators and Credora's
input/output contract. External tensor data and custom operator/opset domains
are rejected; an export requiring them is not accepted. An exporter completing
successfully is not proof of compatibility or prediction parity. Check source
model versus ONNX predictions in the export environment, preserve preprocessing
and class-label order, then validate the graph, metadata and dataset in Credora.
This is export-then-upload support for compatible models, not a guarantee for
every framework, converter release or architecture.

Training/baseline dataset references remain restricted to the authenticated owner's
uploads or explicitly approved shared fixture/processed datasets. Metadata cannot
select another account's files or arbitrary server paths.

## Trained sequence development fixtures

The quick deterministic sequence_test_kit remains unchanged. Optional trained
synthetic four-class, 128-token CNN fixtures use a separate development/export
environment. Install Torch and the builder dependencies there directly, not in
the serving environment; CPU Torch is sufficient:

```bat
python -m pip install "torch>=2.2,<3" numpy onnx onnxruntime scikit-learn
python scripts\build_test_sequence_model.py --trained --output-dir data\trained_sequence_test_kit
```

The builder checks strong/weak discrimination, Torch/ONNX parity and saliency
peaking in the known motif. Synthetic fixture accuracy is not guaranteed real
traffic performance. PyTorch is development-only, not a mandatory runtime or CI
dependency.

## Trust, reporting and passwords

Model/report integrity checks use the owner-scoped server artifact registry, not
metadata-supplied hashes. New report `model_artifact` bindings expose only the
registration ID, owner and SHA-256; signed-package reports also bind their source
package. Scans reverify before inference and report publication. Latest-report
and report-signature API requests return HTTP 409 if artifact or citation checks
fail. Dashboard JSON/DOCX downloads check at render time and again on download;
DOCX is regenerated from a checked snapshot instead of trusting a cached export.
Legacy report export fails closed when its artifact cannot be unambiguously
matched to that owner's registered model and verification hash.

Each finding's `module` must identify its containing actual module result and
its `metric` must resolve to `score`, `status`, or a dotted `details` path. Missing
paths, misattributed findings and duplicate actual module IDs reject report
serialization/export. File signing validates citations before signing. This is
structural traceability only: resolving a citation does not prove that a measured
value is true or that the finding's prose is a valid interpretation.

These checks assume a trustworthy server/registry and do not resist an attacker
who changes both the model and its stored baseline or eliminate every concurrent
file replacement race. Stored model/package uploads and extracted models now use
AES-256-GCM encryption, authenticated in-memory reads, read-attempt/completion
audits and a persistent distinct-artifact burst limit. Plaintext SHA-256 baselines
and model sizes retain their original meaning. Source fixtures remain plaintext;
datasets, metadata and reports are outside model-encryption scope. A required
runtime key and explicit verified legacy migration are described in
[protected storage setup and limits](../README.md#phase-3-security-setup-protected-model-storage).
These protections do not resist theft of the key or control of the running server.

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
