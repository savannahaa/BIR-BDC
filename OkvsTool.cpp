// OkvsTool.cpp
#include "OkvsTool.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <string>
#include <vector>
#include <cstring>  // std::memcpy

#include <cryptoTools/Crypto/PRNG.h>      // PRNG
#include <cryptoTools/Common/Defines.h>   // toBlock
#include <cryptoTools/Common/Timer.h>     // Timer

using namespace std;
using namespace osuCrypto;
using namespace oc;
using namespace volePSI;


#include <openssl/evp.h>

static uint64_t hashKeyToValue(const block& key, const block& secret)
{
    uint8_t buf[32]; // SHA256 输出
    unsigned int len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    // 初始化：使用 SHA256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        throw std::runtime_error("DigestInit failed");

    // 固定密钥
    if (EVP_DigestUpdate(ctx, &secret, sizeof(block)) != 1)
        throw std::runtime_error("DigestUpdate secret failed");

    // key
    if (EVP_DigestUpdate(ctx, &key, sizeof(block)) != 1)
        throw std::runtime_error("DigestUpdate key failed");

    // 输出 hash
    if (EVP_DigestFinal_ex(ctx, buf, &len) != 1)
        throw std::runtime_error("DigestFinal failed");

    EVP_MD_CTX_free(ctx);

    // 取前 8 字节得到 uint64_t
    uint64_t val;
    memcpy(&val, buf, sizeof(uint64_t));
    return val;
}


static bool generateAndSaveValues(const vector<block>& keys,
                                  const string& valPath)
{
    cout << "Generating deterministic encrypted values..." << endl;

    ofstream valFile(valPath);
    if (!valFile.is_open()) {
        cerr << "Failed to open " << valPath << endl;
        return false;
    }

    // 固定密钥（用户可以替换）
    block secret = oc::toBlock(0x12345678, 0x90abcdef);

    for (size_t i = 0; i < keys.size(); ++i) {
        uint64_t val = hashKeyToValue(keys[i], secret);
        valFile << val << "\n";
    }

    cout << "Done. Saved " << keys.size() << " values." << endl;
    return true;
}

bool loadKeysAndGenerateValues(
    std::vector<block>& keys,
    oc::Matrix<block>& vals,
    const std::string& keyPath,
    const std::string& valPath)
{
    // 1. 读取 keys
    ifstream keyFile(keyPath);
    if (!keyFile.is_open()) {
        cerr << "Failed to open " << keyPath << endl;
        return false;
    }

    vector<uint64_t> keyInts;
    uint64_t k;
    string line;
    while (getline(keyFile, line)) {
        if (!line.empty()) {
            k = stoull(line);
            keyInts.push_back(k);
        }
    }
    keyFile.close();

    if (keyInts.empty()) {
        cerr << "No keys found in " << keyPath << endl;
        return false;
    }

    size_t n = keyInts.size();
    keys.resize(n);

    // 转成 block
    for (size_t i = 0; i < n; ++i) {
        keys[i] = toBlock(keyInts[i]);
    }

    cout << "Successfully loaded " << n << " keys." << endl;

    // 2. 根据 keys 生成并保存 values
    if (!generateAndSaveValues(keys, valPath)) {
        cerr << "Failed to generate values" << endl;
        return false;
    }

    // 3. 再从 valPath 读回生成好的 values
    ifstream valFile(valPath);
    if (!valFile.is_open()) {
        cerr << "Failed to open generated " << valPath << endl;
        return false;
    }

    vector<uint64_t> valInts;
    uint64_t v;
    while (getline(valFile, line)) {
        if (!line.empty()) {
            v = stoull(line);
            valInts.push_back(v);
        }
    }
    valFile.close();

    vals.resize(n, 1);
    for (size_t i = 0; i < n; ++i) {
        vals(i, 0) = toBlock(valInts[i]);
    }

    cout << "Successfully loaded " << n << " generated values." << endl;
    return true;
}

// 把 oc::Matrix<block> 二进制写入文件： [rows(uint64)] [cols(uint64)] [data]
bool saveMatrixToFile(const oc::Matrix<block>& M, const std::string& path)
{
    ofstream out(path, ios::binary);
    if (!out.is_open()) {
        cerr << "Failed to open " << path << " for writing" << endl;
        return false;
    }

    uint64_t rows = M.rows();
    uint64_t cols = M.cols();

    // 按网络字节序写入（和你原来的代码保持一致）
    uint64_t rn = htobe64(rows);
    uint64_t cn = htobe64(cols);

    out.write(reinterpret_cast<const char*>(&rn), sizeof(rn));
    out.write(reinterpret_cast<const char*>(&cn), sizeof(cn));

    if (rows * cols) {
        out.write(reinterpret_cast<const char*>(M.data()),
                  rows * cols * sizeof(block));
    }

    out.close();
    return true;
}

// 从文件读取 oc::Matrix<block>，格式同上
bool loadMatrixFromFile(oc::Matrix<block>& M, const std::string& path)
{
    ifstream in(path, ios::binary);
    if (!in.is_open()) {
        cerr << "Failed to open " << path << " for reading" << endl;
        return false;
    }

    uint64_t rn = 0, cn = 0;
    in.read(reinterpret_cast<char*>(&rn), sizeof(rn));
    in.read(reinterpret_cast<char*>(&cn), sizeof(cn));

    uint64_t rows = be64toh(rn);
    uint64_t cols = be64toh(cn);

    M.resize(rows, cols);
    if (rows * cols) {
        in.read(reinterpret_cast<char*>(M.data()),
                rows * cols * sizeof(block));
    }

    in.close();
    return true;
}

// ====================== OKVS 编码/解码模板实现 ======================

template<typename T>
static bool encodeOKVS_impl(
    const vector<block>& keys,
    const oc::Matrix<block>& vals,
    oc::Matrix<block>& okvs_out,
    PaxosParam& pp,
    u64 seed)
{
    try {
        Paxos<T> paxos;
        paxos.init(keys.size(), pp, block(seed, seed));
        paxos.setInput(keys);

        size_t rows = pp.size();
        size_t cols = vals.cols();
        okvs_out.resize(rows, cols);

        Timer timer;
        auto encode_start = timer.setTimePoint("encode_start");
        paxos.template encode<block>(vals, okvs_out);
        auto encode_end = timer.setTimePoint("encode_end");

        double ms = chrono::duration_cast<chrono::microseconds>(encode_end - encode_start).count() / 1000.0;
        cout << "[encodeOKVS_impl] encode time: " << ms << " ms" << endl;
        double D_size_MB = (rows * cols * sizeof(block)) / (1024.0 * 1024.0);
        cout << "[encodeOKVS_impl] OKVS D size: " << D_size_MB << " MB" << endl;
        return true;
    } catch (const exception& e) {
        cerr << "encodeOKVS_impl exception: " << e.what() << endl;
        return false;
    }
}

template<typename T>
static bool decodeOKVS_impl(
    const vector<block>& keys,
    const oc::Matrix<block>& okvs_in,
    oc::Matrix<block>& vals_out,
    PaxosParam& pp,
    u64 seed)
{
    try {
        // 初始化阶段（不计入decode时间）
        Paxos<T> paxos;
        paxos.init(keys.size(), pp, block(seed, seed));

        size_t rows = keys.size();
        size_t cols = okvs_in.cols();
        vals_out.resize(rows, cols);

        // 使用Timer测量纯decode时间（与main.cpp一致）
        Timer timer;
        auto decode_start = timer.setTimePoint("decode_start");
        paxos.template decode<block>(keys, vals_out, okvs_in);
        auto decode_end = timer.setTimePoint("decode_end");

        double ms = chrono::duration_cast<chrono::microseconds>(decode_end - decode_start).count() / 1000.0;
        cout << "[decodeOKVS_impl] decode time: " << ms << " ms" << endl;
        return true;
    } catch (const exception& e) {
        cerr << "decodeOKVS_impl exception: " << e.what() << endl;
        return false;
    }
}

// ====================== dispatch：对外真正调用的接口 ======================

bool encodeOKVS_dispatch(
    int bits,
    const std::vector<block>& keys,
    const oc::Matrix<block>& vals,
    oc::Matrix<block>& okvs_out,
    PaxosParam& pp,
    osuCrypto::u64 seed)
{
    switch (bits) {
    case 8:  return encodeOKVS_impl<u8 >(keys, vals, okvs_out, pp, seed);
    case 16: return encodeOKVS_impl<u16>(keys, vals, okvs_out, pp, seed);
    case 32: return encodeOKVS_impl<u32>(keys, vals, okvs_out, pp, seed);
    case 64: return encodeOKVS_impl<u64>(keys, vals, okvs_out, pp, seed);
    default:
        cerr << "Unsupported bit size: " << bits << endl;
        return false;
    }
}

bool decodeOKVS_dispatch(
    int bits,
    const std::vector<block>& keys,
    const oc::Matrix<block>& okvs_in,
    oc::Matrix<block>& vals_out,
    PaxosParam& pp,
    osuCrypto::u64 seed)
{
    switch (bits) {
    case 8:  return decodeOKVS_impl<u8 >(keys, okvs_in, vals_out, pp, seed);
    case 16: return decodeOKVS_impl<u16>(keys, okvs_in, vals_out, pp, seed);
    case 32: return decodeOKVS_impl<u32>(keys, okvs_in, vals_out, pp, seed);
    case 64: return decodeOKVS_impl<u64>(keys, okvs_in, vals_out, pp, seed);
    default:
        cerr << "Unsupported bit size: " << bits << endl;
        return false;
    }
}