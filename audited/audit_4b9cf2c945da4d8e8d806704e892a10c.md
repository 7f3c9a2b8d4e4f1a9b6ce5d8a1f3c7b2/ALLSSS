### Title
Miner Replacement Bypasses Continuous Block Limit via Fresh Counter Reset

### Summary
When `RecordCandidateReplacement` swaps a miner's public key mid-round, the `LatestPubkeyToTinyBlocksCount` counter is not updated to reflect the replacement. The replacement miner receives a fresh counter starting at `minersCountInTheory - 1`, allowing them to produce additional continuous blocks beyond the intended limit designed to prevent centralization and ensure fair block production distribution.

### Finding Description

The vulnerability exists in the interaction between the miner replacement logic and the continuous block counter mechanism:

**Root Cause:** When `RecordCandidateReplacement` is called, it updates the `RealTimeMinersInformation` map by removing the old pubkey and adding the new pubkey, but critically does NOT update the `LatestPubkeyToTinyBlocksCount` state: [1](#0-0) 

**Counter Reset Logic:** When the replacement miner produces their next block, `ResetLatestProviderToTinyBlocksCount` is called. Since `_processingBlockMinerPubkey` (derived from the block signature) equals the new pubkey but `LatestPubkeyToTinyBlocksCount.Pubkey` still contains the old pubkey, the comparison fails at line 352, triggering the "different miner" branch at line 359 which resets the counter: [2](#0-1) 

**Validation Gap:** The `ContinuousBlocksValidationProvider` validates that `BlocksCount` is not negative before allowing block production: [3](#0-2) 

However, since the replacement miner gets a fresh counter, this validation passes even when the original miner would have been blocked.

**Entry Point:** The replacement is triggered via `ReplaceCandidatePubkey` in the Election Contract, which requires candidate admin permission but has no rate limiting: [4](#0-3) 

### Impact Explanation

**Direct Consensus Integrity Impact:**
- The continuous block limit (MaximumTinyBlocksCount = 8) is designed to prevent any single miner from producing too many consecutive blocks, ensuring fair distribution and preventing centralization: [5](#0-4) 

- An attacker controlling MinerA can produce blocks until the counter drops to 1-2 remaining, then replace to MinerB and receive a fresh counter of 7+ blocks
- This allows producing 14+ continuous blocks from a single entity instead of the intended maximum of 8

**Centralization Risk:**
- Defeats the fairness mechanism that distributes block production across multiple miners
- A single entity can maintain disproportionate control over block production by cycling through keypairs

**Network Health:**
- The continuous block limit works in conjunction with the blockchain health monitoring system that adjusts `MaximumBlocksCount` based on LIB progress: [6](#0-5) 

- Bypassing this limit can interfere with the network's ability to maintain consensus health

### Likelihood Explanation

**Attacker Prerequisites:**
- Must be an elected miner (requires significant stake and community support)
- Must control the candidate admin keypair (typical for self-managed nodes)

**Attack Complexity:**
- Low complexity: simply call `ReplaceCandidatePubkey` when the counter is low
- No cooldown period or rate limiting on replacements observed
- The replacement mechanism is a legitimate feature for key rotation, making detection difficult

**Execution Practicality:**
- Fully executable under normal AElf contract semantics
- No special privileges required beyond being an elected miner
- Can be repeated multiple times within a single round

**Economic Rationality:**
- No additional cost beyond the transaction fee for replacement
- Benefit: increased block rewards from producing extra blocks
- Benefit: increased influence over consensus through higher block production share

**Detection Constraints:**
- Legitimate key rotations are indistinguishable from malicious exploitation
- No audit trail linking the counter bypass to the replacement

### Recommendation

**Immediate Fix:**
Modify `RecordCandidateReplacement` to transfer the counter state from the old pubkey to the new pubkey:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");

    if (!TryToGetCurrentRoundInformation(out var currentRound) ||
        !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

    // Transfer LatestPubkeyToTinyBlocksCount state
    if (State.LatestPubkeyToTinyBlocksCount.Value != null &&
        State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == input.OldPubkey)
    {
        State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
        {
            Pubkey = input.NewPubkey,
            BlocksCount = State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount
        };
    }

    // ... existing replacement logic
}
```

**Additional Protections:**
1. Add a cooldown period in `ReplaceCandidatePubkey` to limit replacement frequency per round
2. Add an event log when counter state is transferred during replacement
3. Consider implementing a maximum replacement count per term

**Test Cases:**
1. Test that counter state is preserved when replacement occurs mid-block-production
2. Test that replaced miner cannot bypass continuous block limit
3. Test that multiple replacements in sequence maintain counter correctly

### Proof of Concept

**Initial State:**
- MinerA is an elected miner with admin control
- Current round has 8 miners, so `minersCountInTheory = 8`
- `LatestPubkeyToTinyBlocksCount = null` initially

**Attack Sequence:**

1. **Block Height 100:** MinerA produces first block
   - Counter initialized: `{Pubkey: "MinerA", BlocksCount: 7}`

2. **Block Heights 101-105:** MinerA continues producing blocks
   - Counter decremented each time: 7 → 6 → 5 → 4 → 3
   - After block 105: `{Pubkey: "MinerA", BlocksCount: 2}`

3. **Between blocks:** Admin calls `ReplaceCandidatePubkey`
   - Input: `{OldPubkey: "MinerA", NewPubkey: "MinerB"}`
   - Round information updated: MinerA → MinerB in `RealTimeMinersInformation`
   - Counter state NOT updated: still `{Pubkey: "MinerA", BlocksCount: 2}`

4. **Block Height 106:** MinerB (replacement) produces block
   - `_processingBlockMinerPubkey = "MinerB"` (from signature)
   - `ResetLatestProviderToTinyBlocksCount` compares: `"MinerA" != "MinerB"`
   - Counter RESET: `{Pubkey: "MinerB", BlocksCount: 7}`
   - **Expected:** `{Pubkey: "MinerB", BlocksCount: 2}` (inherited)
   - **Actual:** `{Pubkey: "MinerB", BlocksCount: 7}` (fresh counter)

5. **Block Heights 107-113:** MinerB produces 7 more blocks
   - Counter decrements: 7 → 6 → 5 → 4 → 3 → 2 → 1 → 0

**Result:**
- Total continuous blocks from same entity: 6 (MinerA) + 8 (MinerB) = 14 blocks
- Intended maximum: 8 blocks
- **Exploitation confirmed:** Limit bypassed by 75%

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-157)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-365)
```csharp
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
    {
        LatestPubkeyToTinyBlocksCount currentValue;
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
        }
        else
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-256)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);

        var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
        var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));

        //     Remove origin pubkey from Candidates, DataCentersRankingList and InitialMiners; then add new pubkey.
        var candidates = State.Candidates.Value;
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
        }

        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;

            // Notify Profit Contract to update backup subsidy profiting item.
            if (State.ProfitContract.Value == null)
                State.ProfitContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            
            var oldProfitReceiver = GetProfitsReceiverOrDefault(input.OldPubkey);
            var profitReceiver = oldProfitReceiver.Value.Any()
                ? oldProfitReceiver
                : null;
            RemoveBeneficiary(input.OldPubkey);
            AddBeneficiary(input.NewPubkey, profitReceiver);
        }

        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }

        //     For CandidateVotes and CandidateInformation, just replace value of origin pubkey.
        var candidateVotes = State.CandidateVotes[input.OldPubkey];
        if (candidateVotes != null)
        {
            candidateVotes.Pubkey = newPubkeyBytes;
            State.CandidateVotes[input.NewPubkey] = candidateVotes;
            State.CandidateVotes.Remove(input.OldPubkey);
        }

        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }

        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;

        ReplaceCandidateProfitsReceiver(input.OldPubkey, input.NewPubkey);
        
        Context.Fire(new CandidatePubkeyReplaced
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey
        });

        return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-79)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");

        // If R_LIB + 2 < R < R_LIB + CB1, CB goes to Min(T(L2 * (CB1 - (R - R_LIB)) / A), CB0), while CT stays same as before.
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
        }

        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }

        if (!State.IsPreviousBlockInSevereStatus.Value)
            return AEDPoSContractConstants.MaximumTinyBlocksCount;

        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0
        });
        State.IsPreviousBlockInSevereStatus.Value = false;

        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
```
