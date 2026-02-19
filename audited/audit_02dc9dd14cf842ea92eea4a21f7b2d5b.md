### Title
Continuous Blocks Limit Bypass via RoundNumber Manipulation in UpdateValue/TinyBlock Behaviors

### Summary
The `GetUpdateValueRound` and `GetTinyBlockRound` methods copy RoundNumber directly without validation. While this doesn't enable consensus forks or round replays as originally suspected, it allows malicious miners to bypass the continuous blocks production limit by setting RoundNumber to ≤2 in consensus extra data, skipping critical validation in `ContinuousBlocksValidationProvider`.

### Finding Description

**Root Cause:**
The `GetUpdateValueRound` and `GetTinyBlockRound` methods copy RoundNumber directly from the current round without any validation: [1](#0-0) [2](#0-1) 

For NextRound and NextTerm behaviors, RoundNumber validation exists through `RoundTerminateValidationProvider`: [3](#0-2) 

However, for UpdateValue and TinyBlock behaviors, no such validation occurs. The `ContinuousBlocksValidationProvider` uses the unvalidated `ProvidedRound.RoundNumber` from consensus extra data: [4](#0-3) 

**Exploitation Path:**
1. The validation context sets `ProvidedRound` directly to `ExtraData.Round` from the block header: [5](#0-4) 

2. During `ValidateBeforeExecution`, the recovery methods only merge miner information without touching RoundNumber: [6](#0-5) [7](#0-6) 

3. `ContinuousBlocksValidationProvider` is applied to all behaviors including UpdateValue and TinyBlock: [8](#0-7) 

4. After execution, the recovery corrects the RoundNumber before hash validation, so the manipulation isn't detected: [9](#0-8) 

5. The hash calculation includes RoundNumber, but uses the corrected value from state: [10](#0-9) 

### Impact Explanation

**Concrete Harm:**
A malicious miner who has exhausted their continuous blocks limit (tracked via `LatestPubkeyToTinyBlocksCount.BlocksCount < 0`) can bypass this protection by:
- Setting RoundNumber to 1 or 2 in UpdateValue/TinyBlock consensus extra data
- The check `ProvidedRound.RoundNumber > 2` evaluates to false
- Continuous blocks validation is skipped entirely
- Miner can produce unlimited consecutive blocks

**Impact Severity:**
- **Consensus Disruption**: Single miner monopolizes block production beyond intended limits defined by: [11](#0-10) 

- **Operational DoS**: Other miners starved of block production opportunities
- **Reward Misallocation**: Unfair distribution of mining rewards to the exploiting miner
- **Fairness Violation**: Breaks the intended round-robin block production schedule

**Affected Parties**: All network participants and honest miners

### Likelihood Explanation

**Attacker Capabilities:**
Any miner participating in consensus can exploit this by modifying their node software to:
1. Ignore the advisory `GetConsensusCommand` check: [12](#0-11) 

2. Manually construct UpdateValue/TinyBlock transactions with manipulated RoundNumber
3. Submit blocks with modified consensus extra data

**Attack Complexity**: Low - simple modification of RoundNumber field in consensus extra data generation

**Feasibility**: High - no special permissions or economic resources required beyond being an active miner

**Detection**: Difficult - the manipulated RoundNumber is corrected during recovery, making post-execution detection challenging without inspecting raw block headers

### Recommendation

**Primary Fix:**
Add RoundNumber validation for UpdateValue and TinyBlock behaviors in `ValidateBeforeExecution`:

```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue || 
    extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
{
    if (extraData.Round.RoundNumber != baseRound.RoundNumber)
        return new ValidationResult { 
            Success = false, 
            Message = "Round number mismatch in consensus extra data." 
        };
}
```

**Alternative Fix:**
Modify `ContinuousBlocksValidationProvider` to use `BaseRound.RoundNumber` instead of `ProvidedRound.RoundNumber`:

```csharp
if (validationContext.BaseRound.RoundNumber > 2 && // Use BaseRound instead
    validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
```

**Test Cases:**
1. Verify UpdateValue/TinyBlock with RoundNumber ≠ CurrentRoundNumber is rejected
2. Verify miner at continuous blocks limit cannot bypass by manipulating RoundNumber
3. Verify legitimate UpdateValue/TinyBlock with correct RoundNumber still passes

### Proof of Concept

**Initial State:**
- Current round number: 100 (> 2)
- Multiple miners active (not single-node setup)
- Miner A has `LatestPubkeyToTinyBlocksCount.BlocksCount = -1` (limit exhausted)

**Attack Steps:**
1. Miner A's node calls `GetConsensusCommand` which returns `NextRound` behavior due to exhausted limit
2. Miner A modifies node to ignore this and creates `UpdateValue` transaction instead
3. In consensus extra data generation, miner A sets `Round.RoundNumber = 1` instead of 100
4. During `ValidateBeforeExecution`:
   - `ContinuousBlocksValidationProvider` checks: `1 > 2` = false
   - Continuous blocks check skipped
   - Validation passes
5. Block is accepted and miner A continues producing blocks beyond intended limit

**Expected Result:** Validation should reject the block due to exhausted continuous blocks limit

**Actual Result:** Block is accepted because RoundNumber manipulation bypasses the limit check

**Success Condition:** Miner A produces > `MaximumTinyBlocksCount` consecutive blocks in a single round, violating consensus fairness

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L16-16)
```csharp
            RoundNumber = RoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L63-63)
```csharp
            RoundNumber = RoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-30)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-24)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-32)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L29-35)
```csharp
        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-97)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-206)
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
