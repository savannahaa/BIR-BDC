// p4.cpp
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <iomanip>

#include "OkvsTool.h"
#include "Paxos.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;
using namespace osuCrypto;
using namespace volePSI;
using namespace oc;

// 接收指定长度的数据（循环 recv，确保收满或失败）
bool recvAll(int sock, void* data, size_t len)
{
    char* buf = static_cast<char*>(data);
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t n = ::recv(sock, buf + recvd, len - recvd, 0);
        if (n <= 0) {
            return false;
        }
        recvd += static_cast<size_t>(n);
    }
    return true;
}

int main()
{
    // 1. 准备 keys（用和 p1/p2 完全一致的 keys.csv）
    vector<block> keys;
    oc::Matrix<block> dummyVals;  // 为了复用 loadKeysAndGenerateValues

    string keyPath = "../keys.csv";
    string valPath = "../values.csv";   // 会再生成一次 values.csv，影响不大

    if (!loadKeysAndGenerateValues(keys, dummyVals, keyPath, valPath)) {
        cerr << "[p4] loadKeysAndGenerateValues failed" << endl;
        return 1;
    }

    cout << "[p4] Loaded " << keys.size() << " keys." << endl;

    // 2. 构造和 p1/p2 完全一致的 PaxosParam
    int bits = 64;
    auto w   = 3;
    auto ssp = 40;
    auto dt  = PaxosParam::GF128;

    PaxosParam pp(keys.size(), w, ssp, dt);

    // 3. 建立 server socket，等待 p1、p2 两个客户端连接
    uint16_t port = 9000;   // 与 p1/p2 一致

    int listenSock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        perror("[p4] socket");
        return 1;
    }

    int opt = 1;
    ::setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);   // 监听所有网卡

    if (::bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("[p4] bind");
        ::close(listenSock);
        return 1;
    }

    // backlog 设置为 2，最多挂两条待处理连接
    if (::listen(listenSock, 2) < 0) {
        perror("[p4] listen");
        ::close(listenSock);
        return 1;
    }

    cout << "[p4] Listening on port " << port << " ..." << endl;

    // 用两个矩阵存两个客户端发来的 D
    oc::Matrix<block> D1;
    oc::Matrix<block> D2;

    // 接收两次连接：第一次视为来自 P1，第二次视为来自 P2
    for (int idx = 0; idx < 2; ++idx)
    {
        cout << "[p4] Waiting for client " << (idx + 1) << " ..." << endl;

        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int connSock = ::accept(listenSock,
                                reinterpret_cast<sockaddr*>(&clientAddr),
                                &clientLen);
        if (connSock < 0) {
            perror("[p4] accept");
            ::close(listenSock);
            return 1;
        }

        char clientIpStr[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &clientAddr.sin_addr, clientIpStr, sizeof(clientIpStr));
        cout << "[p4] Accepted connection " << (idx + 1)
             << " from " << clientIpStr << ":" << ntohs(clientAddr.sin_port) << endl;

        // 从该连接接收一个 D：先 rows/cols 再数据
        uint64_t rows_n = 0, cols_n = 0;
        if (!recvAll(connSock, &rows_n, sizeof(rows_n)) ||
            !recvAll(connSock, &cols_n, sizeof(cols_n))) {
            cerr << "[p4] recv rows/cols for client " << (idx + 1) << " failed" << endl;
            ::close(connSock);
            ::close(listenSock);
            return 1;
        }

        uint64_t rows = be64toh(rows_n);
        uint64_t cols = be64toh(cols_n);

        cout << "[p4] Receiving D" << (idx + 1)
             << " matrix: " << rows << " x " << cols << endl;

        oc::Matrix<block> D(rows, cols);
        size_t dataBytes = rows * cols * sizeof(block);

        if (dataBytes > 0) {
            if (!recvAll(connSock, D.data(), dataBytes)) {
                cerr << "[p4] recv D" << (idx + 1) << ".data() failed" << endl;
                ::close(connSock);
                ::close(listenSock);
                return 1;
            }
        }

        
        auto now = std::chrono::system_clock::now();

        // 毫秒
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      now.time_since_epoch()) % 1000;

        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm* local = std::localtime(&t);

        std::cout << std::put_time(local, "%H:%M:%S")
                  << "." << std::setfill('0') << std::setw(3) << ms.count()
                  << std::endl;
        
        cout << "[p4] D" << (idx + 1)
             << " received, bytes = " << (16 + dataBytes) << endl;

        ::close(connSock);

        // 根据 idx 存到 D1 或 D2
        if (idx == 0) {
            D1 = std::move(D);
        } else {
            D2 = std::move(D);
        }
    }

    ::close(listenSock);
    

    // 4. 分别 Decode：从 D1、D2 中恢复出 vals1、vals2
    oc::Matrix<block> vals1;
    oc::Matrix<block> vals2;

    if (!decodeOKVS_dispatch(bits, keys, D1, vals1, pp, 0)) {
        cerr << "[p4] decodeOKVS_dispatch for D1 failed" << endl;
        return 1;
    }

    if (!decodeOKVS_dispatch(bits, keys, D2, vals2, pp, 0)) {
        cerr << "[p4] decodeOKVS_dispatch for D2 failed" << endl;
        return 1;
    }

    cout << "[p4] Decode D1 & D2 OK." << endl;
    
        // 简单检查一下维度是否一致
    if (vals1.rows() != vals2.rows() || vals1.cols() != vals2.cols()) {
        cerr << "[p4] vals1 and vals2 have different shapes: "
             << vals1.rows() << "x" << vals1.cols() << " vs "
             << vals2.rows() << "x" << vals2.cols() << endl;
        return 1;
    }
    auto start = std::chrono::high_resolution_clock::now();

    // 5. 逐元素异或：xorVals = vals1 ⊕ vals2
    oc::Matrix<block> xorVals(vals1.rows(), vals1.cols());
    for (size_t r = 0; r < vals1.rows(); ++r) {
        for (size_t c = 0; c < vals1.cols(); ++c) {
            xorVals(r, c) = vals1(r, c) ^ vals2(r, c);
        }
    }
    // 结束时间
    auto end = std::chrono::high_resolution_clock::now();

    // 得到微秒
    auto duration_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // 转为带小数的毫秒
    double duration_ms = duration_us / 1000.0;

    std::cout << "XOR Time cost: " << std::fixed << std::setprecision(3)
            << duration_ms << " ms" << std::endl;
    

   


    // 打印前 3 个结果做个 sanity check
    cout << "[p4] Show first 3 values of vals1:" << endl;
    for (size_t i = 0; i < std::min<size_t>(3, vals1.rows()); ++i) {
        cout << "vals1[" << i << "] = " << vals1(i, 0) << endl;
    }

    cout << "[p4] Show first 3 values of vals2:" << endl;
    for (size_t i = 0; i < std::min<size_t>(3, vals2.rows()); ++i) {
        cout << "vals2[" << i << "] = " << vals2(i, 0) << endl;
    }

    cout << "[p4] Show first 3 values of xorVals (vals1 ^ vals2):" << endl;
    for (size_t i = 0; i < std::min<size_t>(3, xorVals.rows()); ++i) {
        cout << "xorVals[" << i << "] = " << xorVals(i, 0) << endl;
    }

    cout << "[p4] Done." << endl;
    return 0;
}