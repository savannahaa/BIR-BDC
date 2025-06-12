#pragma once
#include "Defines.h"
#include "RsOprf.h"
#include "sparsehash/dense_hash_map"
#include "cryptoTools/Common/Timer.h"

namespace volePSI
{
    namespace details
    {
        struct RsPsiBase
        {

            u64 mSenderSize = 0;
            u64 mRecverSize = 0;
            u64 mSsp = 0;
            PRNG mPrng;
            bool mMalicious = false;
            bool mCompress = true;
            u64 mNumThreads = 0;
            u64 mMaskSize = 0;
            bool mUseReducedRounds = false;
            bool mDebug = false;

            void init(u64 senderSize, u64 recverSize, u64 statSecParam, block seed, bool malicious, u64 numThreads, bool useReducedRounds = false);

        };
    }

    class RsPsiSender : public details::RsPsiBase, public oc::TimerAdapter
    {
    public:

        RsOprfSender mSender;
        void setMultType(oc::MultType type) { mSender.setMultType(type); };


        Proto run(span<block> inputs, Socket& chl);
    };


    class RsPsiReceiver : public details::RsPsiBase, public oc::TimerAdapter
    {
    public:
        RsOprfReceiver mRecver;
        void setMultType(oc::MultType type) { mRecver.setMultType(type); };

        std::vector<u64> mIntersection;

        Proto run(span<block> inputs, Socket& chl);
    };
}
