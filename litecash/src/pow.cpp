// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
	arith_uint256 nPow;
	nPow.SetCompact(pindexLast->nBits);

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;
    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    if (IsDAAEnabled(params, pindexLast)) {
        return GetNextCashWorkRequired(pindexLast, pblock, params);
    }

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimitFork);

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        // If producing the last 6 block took less than 1h, we keep the same
        // difficulty.
        if (pindexLast->nHeight >= params.LCHHeight && pindexLast->nHeight  <= params.LCHHeight + params.LCHInitBlockCount)
        {
        	    	return bnPowLimit.GetCompact();
        }
	    arith_uint256 bnNew;

	    if (pindexLast->nHeight  >= 1506585 && pindexLast->nHeight  <= params.LCHHeight + params.LCHInitBlockCount + params.DifficultyAdjustmentInterval())
	    {
	    		//we adjustment difficulty  to a reasonable level.
	    		bnNew.SetCompact(0x1aa8946b);

	    		return bnNew.GetCompact();
	    }

        return pindexLast->nBits;
    }


    // Go back by what we want to be 14 days worth of blocks
    // Litecoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentInterval()-1;

    if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
        blockstogoback = params.DifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);
    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
	if (pindexLast->nHeight >= params.LCHHeight && pindexLast->nHeight  <= params.LCHHeight + params.LCHInitBlockCount)//pindexLast->nHeight > params.LCHHeight
	{
        const arith_uint256 bnPowLimit = UintToArith256(params.powLimitFork);
        return (bnPowLimit.GetCompact());;
	}

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;
    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;

    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Litecoin: intermediate uint256 can overflow by 1 bit
    bool fShift = bnNew.bits() > 235;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
/**
 * Compute a target based on the work done between 2 blocks and the time
 * required to produce that work.
 */
static arith_uint256 ComputeTarget(const CBlockIndex *pindexFirst,
                                   const CBlockIndex *pindexLast,
                                   const Consensus::Params &params) {
    assert(pindexLast->nHeight > pindexFirst->nHeight);

    /**
     * From the total work done and the time it took to produce that much work,
     * we can deduce how much work we expect to be produced in the targeted time
     * between blocks.
     */
    arith_uint256 work = pindexLast->nChainWork - pindexFirst->nChainWork;
    work *= params.nPowTargetSpacing;

    // In order to avoid difficulty cliffs, we bound the amplitude of the
    // adjustment we are going to do to a factor in [0.5, 2].
    int64_t nActualTimespan =
        int64_t(pindexLast->nTime) - int64_t(pindexFirst->nTime);
    if (nActualTimespan > 288 * params.nPowTargetSpacing) {
        nActualTimespan = 288 * params.nPowTargetSpacing;
    } else if (nActualTimespan < 72 * params.nPowTargetSpacing) {
        nActualTimespan = 72 * params.nPowTargetSpacing;
    }

    work /= nActualTimespan;

    /**
     * We need to compute T = (2^256 / W) - 1 but 2^256 doesn't fit in 256 bits.
     * By expressing 1 as W / W, we get (2^256 - W) / W, and we can compute
     * 2^256 - W as the complement of W.
     */
    return (-work) / work;
}

/**
 * To reduce the impact of timestamp manipulation, we select the block we are
 * basing our computation on via a median of 3.
 */
static const CBlockIndex *GetSuitableBlock(const CBlockIndex *pindex) {
    assert(pindex->nHeight >= 3);

    /**
     * In order to avoid a block with a very skewed timestamp having too much
     * influence, we select the median of the 3 top most blocks as a starting
     * point.
     */
    const CBlockIndex *blocks[3];
    blocks[2] = pindex;
    blocks[1] = pindex->pprev;
    blocks[0] = blocks[1]->pprev;

    // Sorting network.
    if (blocks[0]->nTime > blocks[2]->nTime) {
        std::swap(blocks[0], blocks[2]);
    }

    if (blocks[0]->nTime > blocks[1]->nTime) {
        std::swap(blocks[0], blocks[1]);
    }

    if (blocks[1]->nTime > blocks[2]->nTime) {
        std::swap(blocks[1], blocks[2]);
    }

    // We should have our candidate in the middle now.
    return blocks[1];
}

/**
 * Compute the next required proof of work using a weighted average of the
 * estimated hashrate per block.
 *
 * Using a weighted average ensure that the timestamp parameter cancels out in
 * most of the calculation - except for the timestamp of the first and last
 * block. Because timestamps are the least trustworthy information we have as
 * input, this ensures the algorithm is more resistant to malicious inputs.
 */
unsigned int GetNextCashWorkRequired(const CBlockIndex *pindexPrev,
                                 const CBlockHeader *pblock,
								 const Consensus::Params &params) {
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev);

    // Special difficulty rule for testnet:
    // If the new block's timestamp is more than 2* 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() >
         pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing)) {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Compute the difficulty based on the full adjustment interval.
    const uint32_t nHeight = pindexPrev->nHeight;
    assert(nHeight >= params.DifficultyAdjustmentInterval());

    // Get the last suitable block of the difficulty interval.
    const CBlockIndex *pindexLast = GetSuitableBlock(pindexPrev);
    assert(pindexLast);

    // Get the first suitable block of the difficulty interval.
    uint32_t nHeightFirst = nHeight - 144;
    const CBlockIndex *pindexFirst =
        GetSuitableBlock(pindexPrev->GetAncestor(nHeightFirst));
    assert(pindexFirst);

    // Compute the target based on time and work done during the interval.
    const arith_uint256 nextTarget =
        ComputeTarget(pindexFirst, pindexLast, params);

    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    if (nextTarget > powLimit) {
        return powLimit.GetCompact();
    }

    return nextTarget.GetCompact();
}

static bool IsDAAEnabled(const Consensus::Params& consensusparams, int nHeight) {
    return nHeight >= consensusparams.DAAHeight;
}

bool IsDAAEnabled(const Consensus::Params& consensusparams, const CBlockIndex *pindexPrev) {
    if (pindexPrev == nullptr) {
        return false;
    }

    return IsDAAEnabled(consensusparams, pindexPrev->nHeight);
}
