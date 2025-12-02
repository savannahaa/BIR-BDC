// OkvsTool.h
#pragma once

#include <vector>
#include <string>
#include <libOTe/Tools/LDPC/Mtx.h>
#include <cryptoTools/Common/Defines.h>
#include "Paxos.h"

using osuCrypto::block;

// 声明你需要在 p1.cpp 里用的函数

bool loadKeysAndGenerateValues(
    std::vector<block>& keys,
    oc::Matrix<block>& vals,
    const std::string& keyPath,
    const std::string& valPath);

bool saveMatrixToFile(
    const oc::Matrix<block>& M,
    const std::string& path);

bool loadMatrixFromFile(
    oc::Matrix<block>& M,
    const std::string& path);

// OKVS 编码/解码对外接口
bool encodeOKVS_dispatch(
    int bits,
    const std::vector<block>& keys,
    const oc::Matrix<block>& vals,
    oc::Matrix<block>& okvs_out,
    volePSI::PaxosParam& pp,        // ★ 加上 volePSI::
    osuCrypto::u64 seed = 0);

bool decodeOKVS_dispatch(
    int bits,
    const std::vector<block>& keys,
    const oc::Matrix<block>& okvs_in,
    oc::Matrix<block>& vals_out,
    volePSI::PaxosParam& pp,        // ★ 同样
    osuCrypto::u64 seed = 0);