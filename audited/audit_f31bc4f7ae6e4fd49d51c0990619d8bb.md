### Title
Malicious Miner Can Manipulate LIB Calculation Through Crafted NextRound Data

### Summary
A malicious miner can provide a crafted `NextRoundInput` with pre-populated `SupposedOrderOfNextRound` values to manipulate which miners are considered "mined" in the Last Irreversible Block (LIB) consensus calculation. This allows the attacker to selectively include only miners with high implied irreversible heights while meeting the 2/3+ threshold, prematurely advancing chain finalization and potentially enabling double-spend or reorganization attacks.

### Finding Description

The vulnerability exists in how the consensus contract handles round transitions and calculates the Last Irreversible Block height.

The LIB calculation uses `GetMinedMiners()` to determine which miners participated in the current round: [1](#0-0) 

This method returns miners where `SupposedOrderOfNextRound != 0`. The list of mined miners is then used to filter which implied irreversible heights from the previous round are considered: [2](#0-1) 

The critical flaw is that when a miner calls `NextRound`, they provide a `NextRoundInput` containing the entire `RealTimeMinersInformation` structure. The `ToRound()` method directly copies this user-provided data: [3](#0-2) 

The legitimate round generation method `GenerateNextRoundInformation` creates new `MinerInRound` entries WITHOUT setting `SupposedOrderOfNextRound` (it defaults to 0): [4](#0-3) 

However, the validation for `NextRound` only checks that the count of miners with `FinalOrderOfNextRound > 0` equals those who mined, but does NOT validate `SupposedOrderOfNextRound` values: [5](#0-4) [6](#0-5) 

The crafted next round data is stored directly via `ProcessNextRound`: [7](#0-6) 

When `ProcessUpdateValue` is subsequently called, it uses the manipulated current round data for LIB calculation: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Violation**: The attacker can manipulate which block height becomes irreversible, undermining the fundamental security guarantee that finalized blocks represent true network consensus. By selectively including only miners with high implied irreversible heights (while still meeting the `MinersCountOfConsent` = 2/3+1 threshold), the attacker pushes the LIB higher than legitimately warranted.

**Double-Spend Risk**: Premature finalization can enable double-spend attacks if the attacker finalizes a chain containing fraudulent transactions before the network achieves true consensus.

**Chain Reorganization Attacks**: By advancing finalization on an attacker-controlled chain fork, legitimate competing chains can be permanently orphaned even if they represent the honest majority.

**Affected Parties**: All network participants relying on block finality guarantees, including exchanges, dApps, and users making irreversible decisions based on finalized blocks.

**Severity**: HIGH - This directly compromises the consensus security model and chain finality guarantees.

### Likelihood Explanation

**Attacker Capabilities**: Any miner in the current validator set can execute this attack. The attacker only needs to:
1. Be part of the legitimate miner set (passes `PreCheck`)
2. Craft a `NextRoundInput` with manipulated `SupposedOrderOfNextRound` values
3. Call `NextRound` when it's their turn to produce the extra block

**Attack Complexity**: LOW - The attack requires:
- No special cryptographic knowledge
- No coordination with other miners
- Simply providing crafted input data to a standard consensus method
- The crafted data passes all existing validation checks

**Feasibility**: HIGH - The preconditions are minimal:
- Attacker is an active miner (by design in PoS systems, miners have this role)
- Network is operating normally
- No special timing or state requirements

**Detection Difficulty**: The attack is subtle because the crafted `NextRoundInput` passes all current validators and appears valid. Detection would require comparing the provided round data against what `GenerateNextRoundInformation` would produce, which the contract currently doesn't do.

**Economic Rationality**: The attack cost is negligible (just the transaction fee for `NextRound`), while the potential gain from manipulating finality could be substantial (enabling profitable double-spends or chain reorganizations).

### Recommendation

**Immediate Fix**: Add validation in `NextRound` processing to ensure `SupposedOrderOfNextRound` values are zero for all miners in the provided next round data:

```csharp
// In ProcessNextRound or validation provider
foreach (var miner in nextRound.RealTimeMinersInformation.Values)
{
    Assert(miner.SupposedOrderOfNextRound == 0, 
        "SupposedOrderOfNextRound must be zero in next round initialization");
    Assert(miner.FinalOrderOfNextRound == 0 || 
           currentRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey) && 
           currentRound.RealTimeMinersInformation[miner.Pubkey].OutValue != null,
        "Invalid FinalOrderOfNextRound assignment");
}
```

**Stronger Fix**: Regenerate the next round data on-chain and compare against the provided input:

```csharp
// In ProcessNextRound
Round expectedNextRound;
currentRound.GenerateNextRoundInformation(Context.CurrentBlockTime, 
    GetBlockchainStartTimestamp(), out expectedNextRound);

// Validate that provided round matches expected (excluding miner-specific fields)
Assert(CompareRounds(nextRound, expectedNextRound), 
    "Provided next round does not match expected generation");
```

**Test Cases**: Add regression tests that:
1. Attempt to call `NextRound` with pre-populated `SupposedOrderOfNextRound` values
2. Verify rejection of manipulated next round data
3. Test LIB calculation with various miner inclusion scenarios
4. Ensure `GetMinedMiners()` only returns miners who actually mined in the current round

### Proof of Concept

**Initial State**:
- Round N has completed with miners A, B, C, D, E all producing blocks
- Each miner reported their `ImpliedIrreversibleBlockHeight` in round N
- Miner A has height 100, B has 105, C has 110, D has 115, E has 120

**Attack Steps**:
1. Malicious miner M (who is miner A) calls `NextRound` to transition to round N+1
2. M crafts `NextRoundInput` where in `RealTimeMinersInformation`:
   - Sets `SupposedOrderOfNextRound = 1` for miners C, D, E (high heights)
   - Sets `SupposedOrderOfNextRound = 0` for miners A, B (low heights)
   - Properly sets `FinalOrderOfNextRound` based on who mined (to pass validation)
3. Validation passes: `NextRoundMiningOrderValidationProvider` only checks `FinalOrderOfNextRound`, not `SupposedOrderOfNextRound`
4. Crafted round N+1 is stored via `AddRoundInformation`
5. When `UpdateValue` is called in round N+1, LIB calculator:
   - Gets `minedMiners` = [C, D, E] (those with `SupposedOrderOfNextRound != 0`)
   - Filters round N heights to [110, 115, 120]
   - Calculates LIB = heights[(3-1)/3] = heights[0] = 110

**Expected Result**: LIB should be calculated using all miners [A,B,C,D,E] with heights [100,105,110,115,120], giving LIB = heights[(5-1)/3] = heights[1] = 105

**Actual Result**: LIB = 110 (advanced by 5 blocks prematurely)

**Success Condition**: The attack succeeds if the LIB calculated in step 5 is higher than what it would be if all legitimate miners were included.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-32)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }
```
