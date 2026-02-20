# Audit Report

## Title
Unvalidated ActualMiningTimes in RecoverFromTinyBlock Enables Term Change Manipulation and Consensus Corruption

## Summary
The AEDPoS consensus system fails to validate that miner-provided `ActualMiningTime` values match the actual block time when processing TinyBlock consensus information. Since `ActualMiningTimes` is excluded from round hash verification but used in critical consensus decisions including term change detection, malicious miners can provide arbitrary timestamps to manipulate consensus timing and disrupt governance processes.

## Finding Description

The vulnerability exists in the TinyBlock processing flow where miner-provided timestamps are accepted without validation.

**Root Cause:**

The `RecoverFromTinyBlock()` function unconditionally adds provided timestamps to the round state without any validation against `Context.CurrentBlockTime`: [1](#0-0) 

Similarly, `ProcessTinyBlock()` persists the provided timestamp directly to blockchain state without comparing it to the actual block time: [2](#0-1) 

**Why Existing Protections Fail:**

1. **Hash Validation Bypass:** The round integrity verification explicitly clears `ActualMiningTimes` before computing hashes, allowing manipulated timestamps to bypass integrity checks: [3](#0-2) 

2. **Validation Uses Corrupted Data:** During `ValidateBeforeExecution`, the system calls `RecoverFromTinyBlock` BEFORE running validation providers, meaning validators check against already-corrupted state: [4](#0-3) 

3. **Time Slot Validation Compromised:** The `TimeSlotValidationProvider` retrieves the latest actual mining time from the already-recovered (corrupted) round data: [5](#0-4) 

**Attack Path:**

A malicious miner producing a TinyBlock can modify the `ActualMiningTimes` in the consensus header after generation but before block signing. The block signature proves the miner signed the block but doesn't validate timestamp accuracy. The only validation is that `SenderPubkey` matches `SignerPubkey`: [6](#0-5) 

The honest implementation sets `ActualMiningTime` to `Context.CurrentBlockTime`: [7](#0-6) 

However, a malicious miner controlling their node software can modify this value before signing.

## Impact Explanation

**Critical Consensus Corruption:**

The `NeedToChangeTerm()` function uses `ActualMiningTimes.Last()` to determine when term transitions should occur: [8](#0-7) 

Attackers can:
- **Delay term changes** by providing past timestamps, extending their mining power and delaying election updates and treasury releases
- **Advance term changes** by providing future timestamps (within the ~4 second block timestamp tolerance window), triggering premature elections and disrupting governance timing

The corrupted timestamps also affect consensus behavior decisions: [9](#0-8) 

**Affected Parties:** All blockchain participants experience consensus instability, governance processes are disrupted with mistimed elections and treasury releases, and miners gain unfair advantages through manipulated consensus timing.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current miner list (untrusted actors in AElf's threat model)
- Must produce TinyBlocks (normal miner operation)
- Must control their node software (standard for block producers)

**Attack Complexity: LOW**

The attack requires only modifying the node software to alter the `ActualMiningTimes` field in the consensus header data between generation and block signing. No cryptographic barriers exist since:
- Block producers control their node software completely
- The signature proves block authorship, not data accuracy
- `ActualMiningTimes` is excluded from hash verification
- No timestamp validation compares provided values against `Context.CurrentBlockTime`

**Feasibility: HIGH** - The attack is technically straightforward for any miner willing to run modified node software. Detection is difficult since observers only see the final persisted timestamps without reference to actual block times.

## Recommendation

Add validation to compare the provided `ActualMiningTime` against `Context.CurrentBlockTime` during both validation and processing:

```csharp
// In ProcessTinyBlock
private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);

    // Validate timestamp accuracy
    var timeDifference = (Context.CurrentBlockTime - tinyBlockInput.ActualMiningTime).Seconds;
    Assert(Math.Abs(timeDifference) <= 1, "ActualMiningTime must match block time");

    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
    minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
    minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

    Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
}
```

Similar validation should be added to `ProcessUpdateValue` and validation providers should verify timestamp accuracy before using `ActualMiningTimes` for consensus decisions.

## Proof of Concept

A malicious miner can execute this attack by:

1. Running modified node software that intercepts consensus extra data generation
2. Modifying the `ActualMiningTime` field in `GetTinyBlockRound` output to an arbitrary timestamp within the block timestamp tolerance window
3. Signing and broadcasting the block with falsified timestamp
4. The block passes validation because no check compares `ActualMiningTime` to `Context.CurrentBlockTime`
5. The falsified timestamp is persisted to state and affects future term change decisions

The vulnerability can be demonstrated by creating a test that:
1. Generates a TinyBlock with honest `ActualMiningTime`
2. Modifies the `ActualMiningTime` in the consensus header before processing
3. Verifies the block is accepted and the falsified timestamp is persisted
4. Checks that `NeedToChangeTerm()` uses the falsified timestamp for term change decisions

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L35-47)
```csharp
    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-243)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }

    /// <summary>
    ///     If periodSeconds == 7:
    ///     1, 1, 1 => 0 != 1 - 1 => false
    ///     1, 2, 1 => 0 != 1 - 1 => false
    ///     1, 8, 1 => 1 != 1 - 1 => true => term number will be 2
    ///     1, 9, 2 => 1 != 2 - 1 => false
    ///     1, 15, 2 => 2 != 2 - 1 => true => term number will be 3.
    /// </summary>
    /// <param name="blockchainStartTimestamp"></param>
    /// <param name="termNumber"></param>
    /// <param name="blockProducedTimestamp"></param>
    /// <param name="periodSeconds"></param>
    /// <returns></returns>
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-60)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-33)
```csharp
    public ByteString ExtractConsensusExtraData(BlockHeader header)
    {
        var consensusExtraData =
            _blockExtraDataService.GetExtraDataFromBlockHeader(_consensusExtraDataProvider.BlockHeaderExtraDataKey,
                header);
        if (consensusExtraData == null)
            return null;

        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L155-171)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForTinyBlock(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = currentRound.GetTinyBlockRound(pubkey),
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-80)
```csharp
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;

                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());

                // If provided pubkey is the one who terminated previous round, he can mine
                // (_maximumBlocksCount + blocksBeforeCurrentRound) blocks
                // because he has two time slots recorded in current round.

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
            }
```
