# libdivide and LibOTe

The library can be cloned and built with networking support as
```
git clone https://github.com/ridiculousfish/libdivide.git
cd libdivide
cmake .
make -j
sudo make install
```


```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTe
mkdir -p out/build/linux
cmake -S . -B out/build/linux -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DFETCH_AUTO=ON -DENABLE_RELIC=ON -DENABLE_ALL_OT=ON -DCOPROTO_ENABLE_BOOST=ON -DENABLE_SILENT_VOLE=ON -DENABLE_SSE=ON
cmake --build out/build/linux
sudo cmake --install out/build/linux
```
# How to call OKVS and OPRF
```
git clone https://github.com/savannahaa/BIR-BDC.git
cd BIR-BDC
mkdir build
cd build
cmake ..
make
./main
```

```
./main -paxos
./main -oprf
```

# Multi-party Data Cleaning

```
cd build
cmake ..
make
./party1

./partyi

./partyn-1

./partyn

```
---

## Baselines

The following baseline implementations are included:

- `kkrt-pdc2-repro/` — pairwise data-cleaning baseline using KKRT-style PSI.
- `vole-pdc2-repro/` — pairwise data-cleaning baseline using VOLE-based PSI.
- `MPSA/` — outsourced/cloud-assisted multi-party private sample alignment.
- `MPSI/` — multi-party private set intersection baseline.
- `libOTe/` — third-party cryptographic library.

> **Note:** All baseline implementations are included for reproducibility and comparison. Original licenses are maintained where applicable.  

---

## Dependencies

- C++17 compatible compiler
- CMake 3.18+
- libOTe
- Standard libraries: Boost (optional), pthreads

---

## Quick Start

### Build Bic-DC

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
