# Bic-DC Reproduction Project

This project is an experiment-oriented reproduction of the paper:

> Bic-DC: Scalable and Privacy-Preserving Multi-Party Collaborative Data Cleaning

The C++ implementation focuses on the protocol logic and measurement harness:

- multi-party data generation with controlled overlap and label conflicts
- Bic-DC-style bicentric data representation and mislabeled-record resolution
- prefix-flipping label mismatch detection
- runtime, communication-size, and correctness metrics
- pairwise and MPSI-style baselines for comparison

## Important Scope Note

This is a faithful protocol-level reproduction for testing correctness and experimental trends. It uses a deterministic PRF-like function and an `OKVS` interface with two backend options.

- `simulated`: dependency-free backend for fast correctness and sweep testing.
- `shallmate`: optional adapter for the Paxos OKVS encode/decode API from ShallMate/OKVS.

The `simulated` backend is not an oblivious production OKVS and should not be used as a privacy-preserving deployment. The `shallmate` backend requires libOTe/cryptoTools to be installed first.

## Quick Start

Build:

```bash
make
```

Run one experiment:

```bash
./build/bicdc_cpp --parties 5 --records 1024 --label-bits 128 --label-domain-bits 20 --conflict-rate 0.1
```

Select the OKVS backend:

```bash
./build/bicdc_cpp --okvs simulated
./build/bicdc_cpp --okvs shallmate
```

Build with ShallMate/OKVS support after installing libOTe:

```bash
make clean
make USE_SHALLMATE_OKVS=1
./build/bicdc_cpp --okvs shallmate --parties 5 --records 1024 --label-bits 128 --label-domain-bits 20
```

If libOTe/cryptoTools are installed in non-standard paths, pass their include and link flags explicitly:

```bash
make USE_SHALLMATE_OKVS=1 \
  SHALLMATE_CPPFLAGS="-Ithird_party/OKVS -I/path/to/libOTe/include -I/path/to/cryptoTools/include" \
  SHALLMATE_LDLIBS="-L/path/to/lib -lcryptoTools -llibOTe"
```

The adapter is implemented in `cpp/src/okvs.cpp`. It maps our byte keys to `oc::block` keys, stores 16-byte protocol values as `oc::block`, calls `volePSI::Paxos<volePSI::u64>::solve<block>()` for encoding, and calls `decode<block>()` for lookup.

Parameter notes:

- `--label-bits`: the masked label-tag length used by prefix-flipping. With the current 16-byte PRF values, use `128` for exact comparison over the full tag.
- `--label-domain-bits`: the synthetic plaintext label space used only when generating fake datasets. For example, `20` means labels are sampled from `[0, 2^20)`.

Output timing columns:

- `runtime_s`: local computation time.
- `comm_MB`: estimated communication volume.
- `okvs_encode_s`: time spent constructing OKVS encodings.
- `okvs_decode_s`: time spent in OKVS decode calls during bicentric resolution.
- `net_1gbps_s`, `net_100mbps_s`, `net_10mbps_s`: estimated transfer time under the corresponding bandwidth, computed as `communication_bytes * 8 / bandwidth_bps`.
- `total_1gbps_s`, `total_100mbps_s`, `total_10mbps_s`: `runtime_s + net_*_s`.

Run a sweep over variables:

```bash
./build/bicdc_cpp --parties 4 6 8 --records 4096 16384 --label-bits 128 --label-domain-bits 20 --json
```

Run C++ tests:

```bash
make test
```

## Project Layout

```text
cpp/
  include/bicdc/  C++ protocol, data, OKVS, crypto headers
  src/            C++ implementation
  tools/          bicdc_cpp experiment CLI
  tests/          C++ smoke tests
Makefile          build, test, and clean targets
```

## Mapping to the Paper

- Algorithm 1, multi-party data representation:
  implemented by `BicDCProtocol::represent()`.
- Algorithm 2, bicentric mislabeled resolution:
  implemented by `BicDCProtocol::resolve()`.
- Prefix-flipping:
  implemented by `complete_prefixes()` and `flipped_prefixes()` in `cpp/src/crypto.cpp`.
- Metrics:
  `RunMetrics` reports online phase timings, simulated communication bytes, token counts, and correctness.
