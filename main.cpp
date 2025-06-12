#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <libOTe/Tools/LDPC/Mtx.h>
#include <libOTe/Tools/LDPC/Util.h>
#include <libOTe_Tests/Common.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Timer.h>
#include "Paxos.h"
#include "PaxosImpl.h"
#include "SimpleIndex.h"
#include "RsPsi.h"
#include "RsOprf.h"
#include <libdivide.h>
using namespace oc;
using namespace volePSI;;
using namespace osuCrypto;
using namespace std;


void testGen(oc::CLP& cmd)
{
	auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
	auto t = cmd.getOr("t", 1ull);
	std::vector<block> key(n);
	PRNG prng(ZeroBlock);
	Timer timer;
	auto start = timer.setTimePoint("start");
	auto end = start;
	for (u64 i = 0; i < t; ++i){
		prng.get<block>(key);
		end = timer.setTimePoint("d" + std::to_string(i));
	}
	
	//std::cout << timer << std::endl;
	auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);
	std::cout << "total " << tt << "ms"<< std::endl;
}

void testAdd(oc::CLP& cmd)
{
	auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
	auto t = cmd.getOr("t", 1ull);
	std::vector<block> key(n),key1(n);
	std::cout << "Size of int: " << sizeof(block) << " bytes" << std::endl;
	PRNG prng(ZeroBlock);
	prng.get<block>(key);
	prng.get<block>(key1);
	Timer timer;
	auto start = timer.setTimePoint("start");
	auto end = start;
	for (u64 i = 0; i < t; ++i){
		for (u64 j = 0; i < n; ++i){
			key[j] = key[j] ^ key1[j];
		}
		end = timer.setTimePoint("d" + std::to_string(i));
	}
	
	//std::cout << timer << std::endl;
	auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);
	std::cout << "total " << tt << "ms"<< std::endl;
}

template<typename T>
void perfPaxosImpl(oc::CLP& cmd)
{
	auto n = cmd.getOr("n", 1ull << cmd.getOr("nn", 10));
	u64 maxN = std::numeric_limits<T>::max() - 1;
	auto t = cmd.getOr("t", 1ull);
	//auto rand = cmd.isSet("rand");
	auto v = cmd.getOr("v", cmd.isSet("v") ? 1 : 0);
	auto w = cmd.getOr("w", 3);
	auto ssp = cmd.getOr("ssp", 40);
	auto dt = cmd.isSet("binary") ? PaxosParam::Binary : PaxosParam::GF128;
	auto cols = cmd.getOr("cols", 0);

	PaxosParam pp(n, w, ssp, dt);
	//std::cout << "e=" << pp.size() / double(n) << std::endl;
	if (maxN < pp.size())
	{
		std::cout << "n must be smaller than the index type max value. " LOCATION << std::endl;
		throw RTE_LOC;
	}

	auto m = cols ? cols : 1;
	std::vector<block> key(n);
	oc::Matrix<block> val(n, m), pax(pp.size(), m);
	PRNG prng(ZeroBlock);
	prng.get<block>(key);
	prng.get<block>(val);

	Timer timer;
	auto start = timer.setTimePoint("start");
	auto end = start;
	for (u64 i = 0; i < t; ++i)
	{
		Paxos<T> paxos;
		paxos.init(n, pp, block(i, i));

		if (v > 1)
			paxos.setTimer(timer);

		if (cols)
		{
			paxos.setInput(key);
			paxos.template encode<block>(val, pax);
			timer.setTimePoint("s" + std::to_string(i));
			paxos.template decode<block>(key, val, pax);
		}
		else
		{

			paxos.template solve<block>(key, oc::span<block>(val), oc::span<block>(pax));
			timer.setTimePoint("s" + std::to_string(i));
			paxos.template decode<block>(key, oc::span<block>(val), oc::span<block>(pax));
		}


		end = timer.setTimePoint("d" + std::to_string(i));
	}

	if (v)
		std::cout << timer << std::endl;

	auto tt = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / double(1000);
	std::cout << "total " << tt << "ms" << std::endl;
	double D_size_MB = (pp.size() * m * sizeof(block)) / (1024.0 * 1024.0);
	std::cout << "D vector size: " << D_size_MB << " MB" << std::endl;
}

void perfPaxos(oc::CLP& cmd)
{
	auto bits = cmd.getOr("b", 16);
	switch (bits)
	{
	case 8:
		perfPaxosImpl<u8>(cmd);
		break;
	case 16:
		perfPaxosImpl<u16>(cmd);
		break;
	case 32:
		perfPaxosImpl<u32>(cmd);
		break;
	case 64:
		perfPaxosImpl<u64>(cmd);
		break;
	default:
		std::cout << "b must be 8,16,32 or 64. " LOCATION << std::endl;
		throw RTE_LOC;
	}

}

void perfOPRF(oc::CLP& cmd)
{
    // 基本参数设置（从perfPSI中提取）
    auto n = 1ull << cmd.getOr("nn", 10);
    auto t = cmd.getOr("t", 1ull);
    auto v = cmd.isSet("v") ? cmd.getOr("v", 1) : 0;
    auto nt = cmd.getOr("nt", 1);
    bool fakeBase = cmd.isSet("fakeBase");
    
    // VOLE类型设置
    auto type = oc::DefaultMultType;
#ifdef ENABLE_INSECURE_SILVER
    type = cmd.isSet("useSilver") ? oc::MultType::slv5 : type;
#endif
#ifdef ENABLE_BITPOLYMUL
    type = cmd.isSet("useQC") ? oc::MultType::QuasiCyclic : type;
#endif

    PRNG prng(ZeroBlock);
    Timer timer, senderTimer, receiverTimer;
    
    std::cout << "OPRF Performance Test: nt=" << nt 
              << " fakeBase=" << int(fakeBase) 
              << " n=" << n << std::endl;

    // 创建OPRF实例（而非完整PSI）
    RsOprfReceiver oprfRecv;
    RsOprfSender oprfSend;
    
    
    // Bin大小设置（PaXoS vs Baxos选择）
    if (cmd.hasValue("bs") || cmd.hasValue("lbs")) {
        u64 binSize = cmd.getOr("bs", 1ull << cmd.getOr("lbs", 15));
        oprfRecv.mBinSize = binSize;
        oprfSend.mBinSize = binSize;
    }
    
    // 设置VOLE类型
    oprfRecv.setMultType(type);
    oprfSend.setMultType(type);
    
    // 生成测试数据
    std::vector<block> receiverInputs(n), oprfOutputs(n);
    prng.get<block>(receiverInputs);
    
    // 设置计时器
    oprfRecv.setTimer(receiverTimer);
    oprfSend.setTimer(senderTimer);
    
    // 创建本地通信socket
    auto sockets = cp::LocalAsyncSocket::makePair();
    
    // 记录时间点
    auto totalStart = std::chrono::high_resolution_clock::now();
    std::vector<std::chrono::high_resolution_clock::time_point> oprfStarts(t), oprfEnds(t);
    
    // 运行OPRF测试
    for (u64 i = 0; i < t; ++i) {
        timer.setTimePoint("trial_" + std::to_string(i) + "_begin");
        
        // 记录OPRF开始时间
        oprfStarts[i] = std::chrono::high_resolution_clock::now();
        
        // 并发运行OPRF协议
        auto recvTask = oprfRecv.receive(receiverInputs, oprfOutputs, 
                                       prng, sockets[0], nt);
        auto sendTask = oprfSend.send(n, prng, sockets[1], nt);
        
        senderTimer.setTimePoint("begin");
        receiverTimer.setTimePoint("begin");
        
        // 等待OPRF协议完成
        auto results = macoro::sync_wait(
            macoro::when_all_ready(std::move(recvTask), std::move(sendTask))
        );
        
        // 记录OPRF结束时间
        oprfEnds[i] = std::chrono::high_resolution_clock::now();
        
        try { 
            std::get<0>(results).result(); 
        } catch(std::exception& e) {
            std::cout << "Receiver error: " << e.what() << std::endl; 
        }
        
        try { 
            std::get<1>(results).result(); 
        } catch(std::exception& e) {
            std::cout << "Sender error: " << e.what() << std::endl; 
        }
        
        timer.setTimePoint("trial_" + std::to_string(i) + "_end");
    }
    
    auto totalEnd = std::chrono::high_resolution_clock::now();
    
    // 输出性能统计
    if (v) {
        std::cout << "\n=== OPRF Performance Results ===" << std::endl;
        
        // 计算总时间
        auto totalTime = std::chrono::duration_cast<std::chrono::microseconds>(
            totalEnd - totalStart
        ).count() / 1000.0;
        
        // 计算纯OPRF时间
        double totalOprfTime = 0;
        for (u64 i = 0; i < t; ++i) {
            auto oprfTime = std::chrono::duration_cast<std::chrono::microseconds>(
                oprfEnds[i] - oprfStarts[i]
            ).count() / 1000.0;
            totalOprfTime += oprfTime;
        }
        
        std::cout << "Overall timing:" << std::endl;
        std::cout << "Total time: " << totalTime << " ms" << std::endl;
        std::cout << "Pure OPRF time: " << totalOprfTime << " ms" << std::endl;
        std::cout << "Average OPRF time per trial: " << totalOprfTime / t << " ms" << std::endl;
        std::cout << "OPRF time per element: " << totalOprfTime / (t * n) << " ms/element" << std::endl;
        
        std::cout << "\nCommunication:" << std::endl;
        std::cout << "Sender sent: " << sockets[1].bytesSent() << " bytes" << std::endl;
        std::cout << "Receiver sent: " << sockets[0].bytesSent() << " bytes" << std::endl;
        std::cout << "Total communication: " 
                  << (sockets[0].bytesSent() + sockets[1].bytesSent()) 
                  << " bytes" << std::endl;
        
        double bitsPerElement = (sockets[0].bytesSent() + sockets[1].bytesSent()) * 8.0 / n;
        std::cout << "Bits per element: " << bitsPerElement << std::endl;
        
        if (v > 1) {
            std::cout << "\nDetailed timing:" << std::endl;
            std::cout << "Sender:\n" << senderTimer << std::endl;
            std::cout << "Receiver:\n" << receiverTimer << std::endl;
            std::cout << "\nOPRF timing breakdown:" << std::endl;
            for (u64 i = 0; i < t; ++i) {
                auto oprfTime = std::chrono::duration_cast<std::chrono::microseconds>(
                    oprfEnds[i] - oprfStarts[i]
                ).count() / 1000.0;
                std::cout << "Trial " << i << ": " << oprfTime << " ms" << std::endl;
            }
        }
    }
}
int main(int argc, char** argv){
    CLP cmd;
    cmd.parse(argc, argv);
    if (cmd.isSet("paxos")) {
        perfPaxos(cmd);  
    } else if (cmd.isSet("gen")) {
        testGen(cmd);
    } else if (cmd.isSet("oprf")) {
        perfOPRF(cmd);
    } else {
        testAdd(cmd);
    }
    return 0;
}
