#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <thread>
#include <memory>
#include <random>

// libOTe headers
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"

// VOLE PSI headers
#include "volePSI/RsPsi.h"
#include "coproto/Socket/AsioSocket.h"

using namespace oc;
using namespace volePSI;
using namespace std;

// 生成测试集合
vector<block> generateTestSet(size_t setSize, size_t startValue = 0) {
    vector<block> set(setSize);
    for (size_t i = 0; i < setSize; ++i) {
        set[i] = block(0, startValue + i);
    }
    return set;
}

// 打印block值（用于调试）
void printSet(const vector<block>& set, const string& name, size_t maxPrint = 10) {
    cout << name << " (showing first " << min(maxPrint, set.size()) << " elements):" << endl;
    for (size_t i = 0; i < min(maxPrint, set.size()); ++i) {
        cout << "  [" << i << "]: " << set[i] << endl;
    }
    if (set.size() > maxPrint) {
        cout << "  ... and " << (set.size() - maxPrint) << " more elements" << endl;
    }
}

// 发送方实现
void runSender(const vector<block>& senderSet, 
               const string& ip, 
               int port,
               size_t receiverSize,
               bool malicious = false,
               bool verbose = true) {
    
    if (verbose) {
        cout << "=== VOLE PSI Sender ===" << endl;
        cout << "Sender set size: " << senderSet.size() << endl;
        cout << "Expected receiver set size: " << receiverSize << endl;
        cout << "Security model: " << (malicious ? "Malicious" : "Semi-honest") << endl;
        cout << "Connecting to " << ip << ":" << port << endl;
    }

    try {
        // 创建网络连接
        IOService ios;
        Session session(ios, ip, port, SessionMode::Client);
        Channel channel = session.addChannel();
        
        if (verbose) {
            cout << "Connection established!" << endl;
        }

        // 初始化发送方
        RsPsiSender sender;
        
        // 设置参数
        u64 senderSize = senderSet.size();
        u64 receiverSize_u64 = receiverSize;
        u64 statSecParam = 40; // 统计安全参数
        block seed = sysRandomSeed(); // 随机种子
        u64 numThreads = 1;
        
        // 设置乘法类型
        sender.setMultType(DefaultMultType);
        
        // 设置调试模式
        if (verbose) {
            sender.mDebug = true;
        }
        
        // 初始化发送方
        sender.init(senderSize, receiverSize_u64, statSecParam, seed, malicious, numThreads);
        
        if (verbose) {
            cout << "Sender initialized, starting PSI protocol..." << endl;
        }
        
        // 开始计时
        Timer timer;
        timer.setTimePoint("start");
        
        // 运行PSI协议
        macoro::sync_wait(sender.run(senderSet, channel));
        
        // 刷新通道
        macoro::sync_wait(channel.flush());
        
        auto end = timer.setTimePoint("end");
        
        if (verbose) {
            cout << "PSI protocol completed!" << endl;
            cout << "Time taken: " << 
                chrono::duration_cast<chrono::milliseconds>(end - timer.getTimePoint("start")).count() 
                << " ms" << endl;
        }
        
        // 关闭连接
        channel.close();
        
    } catch (const exception& e) {
        cerr << "Sender error: " << e.what() << endl;
        throw;
    }
}

// 接收方实现
void runReceiver(const vector<block>& receiverSet,
                 int port,
                 size_t senderSize,
                 bool malicious = false,
                 bool verbose = true) {
    
    if (verbose) {
        cout << "=== VOLE PSI Receiver ===" << endl;
        cout << "Receiver set size: " << receiverSet.size() << endl;
        cout << "Expected sender set size: " << senderSize << endl;
        cout << "Security model: " << (malicious ? "Malicious" : "Semi-honest") << endl;
        cout << "Listening on port " << port << endl;
    }

    try {
        // 创建网络连接
        IOService ios;
        Session session(ios, "localhost", port, SessionMode::Server);
        Channel channel = session.addChannel();
        
        if (verbose) {
            cout << "Waiting for connection..." << endl;
        }
        
        // 等待连接建立
        channel.waitForConnection();
        
        if (verbose) {
            cout << "Connection established!" << endl;
        }

        // 初始化接收方
        RsPsiReceiver receiver;
        
        // 设置参数
        u64 senderSize_u64 = senderSize;
        u64 receiverSize_u64 = receiverSet.size();
        u64 statSecParam = 40; // 统计安全参数
        block seed = sysRandomSeed(); // 随机种子
        u64 numThreads = 1;
        
        // 设置乘法类型
        receiver.setMultType(DefaultMultType);
        
        // 设置调试模式
        if (verbose) {
            receiver.mDebug = true;
        }
        
        // 初始化接收方
        receiver.init(senderSize_u64, receiverSize_u64, statSecParam, seed, malicious, numThreads);
        
        if (verbose) {
            cout << "Receiver initialized, starting PSI protocol..." << endl;
        }
        
        // 开始计时
        Timer timer;
        timer.setTimePoint("start");
        
        // 运行PSI协议
        macoro::sync_wait(receiver.run(receiverSet, channel));
        
        // 刷新通道
        macoro::sync_wait(channel.flush());
        
        auto end = timer.setTimePoint("end");
        
        if (verbose) {
            cout << "PSI protocol completed!" << endl;
            cout << "Time taken: " << 
                chrono::duration_cast<chrono::milliseconds>(end - timer.getTimePoint("start")).count() 
                << " ms" << endl;
        }
        
        // 关闭连接
        channel.close();
        
    } catch (const exception& e) {
        cerr << "Receiver error: " << e.what() << endl;
        throw;
    }
}

// 单机模拟运行（用于测试）
void runLocalSimulation(size_t senderSize, size_t receiverSize, size_t intersectionSize, bool verbose = true) {
    if (verbose) {
        cout << "=== Local Simulation Mode ===" << endl;
        cout << "Sender set size: " << senderSize << endl;
        cout << "Receiver set size: " << receiverSize << endl;
        cout << "Expected intersection size: " << intersectionSize << endl;
    }
    
    // 生成测试集合
    vector<block> senderSet = generateTestSet(senderSize, 0);
    vector<block> receiverSet = generateTestSet(receiverSize, senderSize - intersectionSize);
    
    if (verbose) {
        printSet(senderSet, "Sender Set");
        printSet(receiverSet, "Receiver Set");
    }
    
    // 在单独的线程中运行接收方
    thread receiverThread([&]() {
        try {
            runReceiver(receiverSet, 12345, senderSize, false, verbose);
        } catch (const exception& e) {
            cerr << "Receiver thread error: " << e.what() << endl;
        }
    });
    
    // 等待一段时间让接收方启动
    this_thread::sleep_for(chrono::milliseconds(1000));
    
    // 在主线程中运行发送方
    try {
        runSender(senderSet, "localhost", 12345, receiverSize, false, verbose);
    } catch (const exception& e) {
        cerr << "Sender thread error: " << e.what() << endl;
    }
    
    // 等待接收方线程完成
    receiverThread.join();
    
    if (verbose) {
        cout << "Simulation completed!" << endl;
    }
}

// 打印使用说明
void printUsage(const string& programName) {
    cout << "VOLE PSI Demo Usage:" << endl;
    cout << "  " << programName << " --help" << endl;
    cout << "  " << programName << " --simulate [options]" << endl;
    cout << "  " << programName << " --sender [options]" << endl;
    cout << "  " << programName << " --receiver [options]" << endl;
    cout << endl;
    cout << "Options:" << endl;
    cout << "  --help                    Show this help message" << endl;
    cout << "  --simulate               Run local simulation" << endl;
    cout << "  --sender                 Run as sender" << endl;
    cout << "  --receiver               Run as receiver" << endl;
    cout << "  --senderSize <size>      Sender set size (default: 1000)" << endl;
    cout << "  --receiverSize <size>    Receiver set size (default: 1000)" << endl;
    cout << "  --intersection <size>    Intersection size for simulation (default: 100)" << endl;
    cout << "  --ip <address>           IP address to connect to (default: localhost)" << endl;
    cout << "  --port <port>            Port number (default: 12345)" << endl;
    cout << "  --malicious              Use malicious security model" << endl;
    cout << "  --quiet                  Reduce output verbosity" << endl;
    cout << endl;
    cout << "Examples:" << endl;
    cout << "  " << programName << " --simulate --senderSize 10000 --receiverSize 8000 --intersection 500" << endl;
    cout << "  " << programName << " --receiver --receiverSize 5000 --port 12345" << endl;
    cout << "  " << programName << " --sender --senderSize 5000 --ip 192.168.1.100 --port 12345" << endl;
}

int main(int argc, char* argv[]) {
    // 解析命令行参数
    CLP cmd;
    cmd.parse(argc, argv);
    
    // 检查是否显示帮助
    if (cmd.isSet("help") || cmd.isSet("h")) {
        printUsage(argv[0]);
        return 0;
    }
    
    // 获取参数
    bool simulate = cmd.isSet("simulate");
    bool sender = cmd.isSet("sender");
    bool receiver = cmd.isSet("receiver");
    
    size_t senderSize = cmd.getOr("senderSize", size_t(1000));
    size_t receiverSize = cmd.getOr("receiverSize", size_t(1000));
    size_t intersectionSize = cmd.getOr("intersection", size_t(100));
    
    string ip = cmd.getOr("ip", string("localhost"));
    int port = cmd.getOr("port", 12345);
    
    bool malicious = cmd.isSet("malicious");
    bool verbose = !cmd.isSet("quiet");
    
    // 验证参数
    if (simulate + sender + receiver != 1) {
        cerr << "Error: Must specify exactly one of --simulate, --sender, or --receiver" << endl;
        printUsage(argv[0]);
        return 1;
    }
    
    try {
        if (simulate) {
            // 运行本地模拟
            runLocalSimulation(senderSize, receiverSize, intersectionSize, verbose);
        } else if (sender) {
            // 运行发送方
            vector<block> senderSet = generateTestSet(senderSize);
            if (verbose) {
                printSet(senderSet, "Sender Set");
            }
            runSender(senderSet, ip, port, receiverSize, malicious, verbose);
        } else if (receiver) {
            // 运行接收方
            vector<block> receiverSet = generateTestSet(receiverSize);
            if (verbose) {
                printSet(receiverSet, "Receiver Set");
            }
            runReceiver(receiverSet, port, senderSize, malicious, verbose);
        }
        
        cout << "Program completed successfully!" << endl;
        return 0;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
}
