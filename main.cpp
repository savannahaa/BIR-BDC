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
			key[j] = key[j]+key1[j];
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




int main(int argc, char** argv){
    CLP cmd;
    cmd.parse(argc, argv);
    if (cmd.isSet("paxos")) {
        perfPaxosImpl<u32>(cmd);  // 使用u32作为默认索引类型
    } else if (cmd.isSet("gen")) {
        testGen(cmd);
    } else {
        testAdd(cmd);
    }
    return 0;
}
