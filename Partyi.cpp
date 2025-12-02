
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


bool sendAll(int sock, const void* data, size_t len)
{
    const char* buf = static_cast<const char*>(data);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(sock, buf + sent, len - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

int main()
{
    vector<block> keys;
    oc::Matrix<block> vals;

    string keyPath = "../keys.csv";
    string valPath = "../values.csv";


    if (!loadKeysAndGenerateValues(keys, vals, keyPath, valPath)) {
        cerr << "[p2] loadKeysAndGenerateValues failed" << endl;
        return 1;
    }

    cout << "[p2] Loaded " << keys.size()
         << " keys, vals.rows() = " << vals.rows()
         << ", vals.cols() = " << vals.cols() << endl;

    
    int bits = 64;
    auto w   = 3;
    auto ssp = 40;
    auto dt  = PaxosParam::GF128;

    PaxosParam pp(keys.size(), w, ssp, dt);

    oc::Matrix<block> D;  
    if (!encodeOKVS_dispatch(bits, keys, vals, D, pp, 0)) {
        cerr << "[p2] encodeOKVS_dispatch failed" << endl;
        return 1;
    }

    cout << "[p2] D encoded: " << D.rows() << " x " << D.cols() << endl;

   
    const char* serverIp = "172.24.122.107"; 
    uint16_t port = 9000;             

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[p2] socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, serverIp, &addr.sin_addr) <= 0) {
        cerr << "[p2] invalid server ip: " << serverIp << endl;
        ::close(sock);
        return 1;
    }
    cout << "[p2] Connecting to " << serverIp << ":" << port << " ..." << endl;
    if (::connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("[p2] connect");
        ::close(sock);
        return 1;
    }
    cout << "[p2] Connected." << endl;


    auto now = std::chrono::system_clock::now();

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;

    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm* local = std::localtime(&t);

    std::cout << std::put_time(local, "%H:%M:%S")
              << "." << std::setfill('0') << std::setw(3) << ms.count()
              << std::endl;
   
    uint64_t rows = D.rows();
    uint64_t cols = D.cols();
    uint64_t rows_n = htobe64(rows);
    uint64_t cols_n = htobe64(cols);

   
    if (!sendAll(sock, &rows_n, sizeof(rows_n)) ||
        !sendAll(sock, &cols_n, sizeof(cols_n))) {
        cerr << "[p2] send rows/cols failed" << endl;
        ::close(sock);
        return 1;
    }

  
    size_t dataBytes = rows * cols * sizeof(block);
    if (dataBytes > 0) {
        if (!sendAll(sock, D.data(), dataBytes)) {
            cerr << "[p2] send D.data() failed" << endl;
            ::close(sock);
            return 1;
        }
    }

    cout << "[p2] Sent D to server, bytes = " << (16 + dataBytes) << endl;

    ::close(sock);
    cout << "[p2] Done." << endl;
    return 0;
}
