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
The protocol initiates by concurrently activating Party1 through Partyn. Subsequently, Party1 generates cryptographic keys ki for each i in the range 2 ≤ i ≤ n−2 and securely transmits each key ki to the corresponding Partyi. Upon receipt, each Partyi (where 2 ≤ i ≤ n−2) encrypts its local data using the received key ki to produce an encrypted value. These values are then subjected to OKVS encoding, resulting in an encoded structure D, which is forwarded to Party1. Thereafter, Party1 employs the keys ki (for 2 ≤ i ≤ n−2) to encrypt and XOR the aggregated data, generating a new set of encrypted outputs. This updated data is again processed via OKVS encoding to form the revised structure D, which is subsequently transmitted to Partyn. Finally, Partyn−1 and Partyn engage in a joint computation phase to perform data cleansing and finalize the protocol.

cd build
cmake ..
make
./party1

./partyi

./partyn-1

./partyn

```
