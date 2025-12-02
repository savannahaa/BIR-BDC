// p4.cpp
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
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
    vector<block> keys;
    oc::Matrix<block> dummyVals;  // 为了复用 loadKeysAndGenerateValues

    string keyPath = "../keys.csv";
    string valPath = "../values.csv";   // 会再生成一次 values.csv，影响不大

    if (!loadKeysAndGenerateValues(keys, dummyVals, keyPath, valPath)) {
        cerr << "[p5] loadKeysAndGenerateValues failed" << endl;
        return 1;
    }

    cout << "[p5] Loaded " << keys.size() << " keys." << endl;

    int bits = 64;
    auto w   = 3;
    auto ssp = 40;
    auto dt  = PaxosParam::GF128;

    PaxosParam pp(keys.size(), w, ssp, dt);

    uint16_t port = 9000;   // 与 p1 一致

    int listenSock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        perror("[p5] socket");
        return 1;
    }

    int opt = 1;
    ::setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);   // 监听所有网卡

    if (::bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("[p5] bind");
        ::close(listenSock);
        return 1;
    }

    if (::listen(listenSock, 1) < 0) {
        perror("[p5] listen");
        ::close(listenSock);
        return 1;
    }

    cout << "[p5] Listening on port " << port << " ..." << endl;

    sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    int connSock = ::accept(listenSock,
                            reinterpret_cast<sockaddr*>(&clientAddr),
                            &clientLen);
    if (connSock < 0) {
        perror("[p5] accept");
        ::close(listenSock);
        return 1;
    }

    char clientIpStr[INET_ADDRSTRLEN] = {0};
    ::inet_ntop(AF_INET, &clientAddr.sin_addr, clientIpStr, sizeof(clientIpStr));
    cout << "[p5] Accepted connection from "
         << clientIpStr << ":" << ntohs(clientAddr.sin_port) << endl;

    // 4. 从 socket 接收 D：先 rows/cols 再数据
    uint64_t rows_n = 0, cols_n = 0;
    if (!recvAll(connSock, &rows_n, sizeof(rows_n)) ||
        !recvAll(connSock, &cols_n, sizeof(cols_n))) {
        cerr << "[p5] recv rows/cols failed" << endl;
        ::close(connSock);
        ::close(listenSock);
        return 1;
    }

    uint64_t rows = be64toh(rows_n);
    uint64_t cols = be64toh(cols_n);

    cout << "[p5] Receiving D matrix: " << rows << " x " << cols << endl;

    oc::Matrix<block> D(rows, cols);
    size_t dataBytes = rows * cols * sizeof(block);

    if (dataBytes > 0) {
        if (!recvAll(connSock, D.data(), dataBytes)) {
            cerr << "[p5] recv D.data() failed" << endl;
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
    double MB = dataBytes / (1024.0 * 1024.0);
    cout << "[p5] Received matrix dataBytes = " << dataBytes 
     << " bytes (" << MB << " MB)" << endl;

    ::close(connSock);
    ::close(listenSock);

    // 5. Decode：从 D 中恢复出 vals
    oc::Matrix<block> decoded;
    if (!decodeOKVS_dispatch(bits, keys, D, decoded, pp, 0)) {
        cerr << "[p5] decodeOKVS_dispatch failed" << endl;
        return 1;
    }

    cout << "[p5] Decode OK. Show first 3 values:" << endl;
    for (size_t i = 0; i < std::min<size_t>(3, keys.size()); ++i) {
        cout << "decoded[" << i << "] = " << decoded(i, 0) << endl;
    }

    cout << "[p5] Done." << endl;
    return 0;
}