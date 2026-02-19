### Title
Missing Pubkey Validation in Round Transitions Allows LIB Consensus Manipulation

### Summary
The `NextRound` and `NextTerm` methods lack validation to ensure that `MinerInRound.Pubkey` fields are non-empty and consistent with dictionary keys. A malicious extra block producer can inject round data with empty/null pubkeys for other miners, causing those miners to be incorrectly excluded from Last Irreversible Block (LIB) consensus calculations in `GetSortedImpliedIrreversibleBlockHeights()`. This breaks Byzantine Fault Tolerance assumptions and persists across subsequent rounds.

### Finding Description

The vulnerability exists in the round transition logic where external input is accepted without proper validation: [1](#0-0) 

The `GetSortedImpliedIrreversibleBlockHeights()` method filters miners using `specificPublicKeys.Contains(i.Pubkey)`. If `i.Pubkey` is null or empty string, and `specificPublicKeys` contains actual hex pubkeys, the `Contains()` check returns false, filtering out that miner from LIB calculation.

**Root Cause:**

When processing `NextRound` or `NextTerm`, the contract converts input directly to a Round object without validating pubkey values: [2](#0-1) [3](#0-2) 

The `ToRound()` method copies `RealTimeMinersInformation` directly without validation, allowing malicious data where dictionary keys are valid pubkeys but the corresponding `MinerInRound.Pubkey` fields are empty or null.

**Why Existing Protections Fail:**

The validation system has multiple providers but NONE check pubkey values: [4](#0-3) 

- `MiningPermissionValidationProvider` checks if sender is in `RealTimeMinersInformation.Keys` (dictionary keys), not the `Pubkey` field values [5](#0-4) 

- `NextRoundMiningOrderValidationProvider` only validates counts, not pubkey values [6](#0-5) 

- `RoundTerminateValidationProvider` checks round numbers and InValues, not pubkeys [7](#0-6) 

**Cascade Effect:**

The vulnerability persists across rounds because `GenerateNextRoundInformation()` copies pubkeys from the previous round: [8](#0-7) 

If round R has empty pubkeys, round R+1 will copy those empty pubkeys, cascading the issue until a `NextTerm` regenerates from the Election contract's miner list.

### Impact Explanation

**Concrete Harm:**
- Miners with empty `Pubkey` fields are excluded from LIB consensus calculation
- LIB calculation uses the formula: `heights[(count-1)/3]` to achieve Byzantine Fault Tolerance [9](#0-8) 

- Excluding miners reduces the heights array, potentially allowing an attacker to:
  - Delay LIB progression by excluding miners with higher implied irreversible block heights
  - Inappropriately accelerate LIB by excluding miners with lower heights
  - Break the 2/3+1 consensus requirement if more than 1/3 of miners are excluded

**Who is Affected:**
- All network participants relying on LIB for transaction finality
- Cross-chain operations depending on confirmed irreversible block heights
- Applications that need finality guarantees

**Severity Justification:**
LIB (Last Irreversible Block) is a critical consensus primitive that determines transaction finality. Manipulating it undermines the entire security model of the blockchain.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a current miner in the round (achievable through staking/voting in Election contract)
- Must be selected as extra block producer (probability 1/N where N = number of miners, typically 1/17 to 1/23)
- Can craft arbitrary `NextRoundInput` messages with malicious pubkey values

**Attack Complexity:**
1. Wait to be selected as extra block producer
2. When producing the final block of the round, craft a malicious `NextRoundInput` where other miners' `MinerInRound.Pubkey` fields are set to empty string while keeping dictionary keys valid
3. Submit `NextRound` transaction with this malicious input
4. Validation passes (no pubkey value checks exist)
5. Malicious round is stored and used for subsequent LIB calculations

**Feasibility Conditions:**
- No special privileges beyond being a miner required
- No transaction fee barriers (normal block production cost)
- Effect persists automatically across rounds via `GenerateNextRoundInformation`

**Detection Constraints:**
- Difficult to detect without monitoring round transition data
- Appears as valid consensus behavior to external observers
- Affected miners can still produce blocks (dictionary keys remain valid)

**Probability:**
Medium-High. While requiring extra block producer selection (1/N chance per round), once achieved, the attack succeeds with certainty due to missing validation and persists across multiple rounds.

### Recommendation

**Code-Level Mitigation:**

Add validation in `NextRoundInput.ToRound()` and `NextTermInput.ToRound()` to enforce pubkey integrity:

```csharp
public Round ToRound()
{
    // Validate all pubkeys are non-empty and match dictionary keys
    foreach (var kvp in RealTimeMinersInformation)
    {
        if (string.IsNullOrEmpty(kvp.Key))
            throw new AssertionException("Dictionary key cannot be empty");
        if (string.IsNullOrEmpty(kvp.Value.Pubkey))
            throw new AssertionException($"Miner pubkey cannot be empty for key {kvp.Key}");
        if (kvp.Key != kvp.Value.Pubkey)
            throw new AssertionException($"Pubkey mismatch: key={kvp.Key}, value.Pubkey={kvp.Value.Pubkey}");
    }
    
    return new Round { /* existing copy logic */ };
}
```

**Additional Invariant Checks:**

For `NextRound` behavior, add validation in `NextRoundMiningOrderValidationProvider` to ensure the miner list hasn't changed:

```csharp
// Verify miner pubkeys match between base round and provided round
var baseKeys = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
var providedKeys = providedRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
if (!baseKeys.SequenceEqual(providedKeys))
{
    return new ValidationResult { Message = "Miner list changed during NextRound" };
}
```

**Test Cases:**

1. Test that `NextRound` with empty pubkey fields is rejected
2. Test that `NextRound` with mismatched key/value pubkeys is rejected
3. Test that `NextRound` with changed miner list is rejected (should only happen in NextTerm)
4. Test LIB calculation with various miner participation patterns to ensure correctness

### Proof of Concept

**Required Initial State:**
- Network with N miners (e.g., N=17)
- Attacker is a legitimate miner (has staked and been elected)
- Current round R with all miners having valid pubkeys

**Attack Steps:**

1. **Wait for Selection:** Attacker waits until selected as extra block producer for round R (1/17 probability)

2. **Craft Malicious Input:** When it's time to call `NextRound`, attacker constructs a `NextRoundInput` for round R+1:
   ```
   NextRoundInput {
     RoundNumber: R+1,
     RealTimeMinersInformation: {
       "AttackerPubkey": MinerInRound { Pubkey: "AttackerPubkey", ... },
       "VictimPubkey1": MinerInRound { Pubkey: "", ... },  // Empty!
       "VictimPubkey2": MinerInRound { Pubkey: "", ... },  // Empty!
       ... // 5 more miners with empty pubkeys (total 7 out of 17)
     }
   }
   ```

3. **Submit Transaction:** Call `NextRound(maliciousInput)` 

4. **Validation Passes:** All existing validations pass because they don't check pubkey values

5. **Malicious Round Stored:** Round R+1 is stored with 7 miners having empty `Pubkey` fields

6. **LIB Calculation Affected:** In subsequent blocks of round R+1 and beyond:
   - `GetMinedMiners()` returns miners with `SupposedOrderOfNextRound != 0`
   - Their `Pubkey` field is read: 7 miners return `""`
   - `GetSortedImpliedIrreversibleBlockHeights(minedMiners)` filters using `Contains("")`
   - Those 7 miners are excluded from LIB calculation
   - LIB is calculated from only 10 miners instead of 17

**Expected vs Actual Result:**
- **Expected:** LIB calculated from all active miners (17), achieving proper 2/3+1 consensus
- **Actual:** LIB calculated from only 10 miners (60% instead of 100%), breaking consensus guarantees

**Success Condition:** 
Monitor `IrreversibleBlockFound` events and verify LIB progression is manipulated (delayed or accelerated compared to honest calculation with all 17 miners).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L12-19)
```csharp
    public List<long> GetSortedImpliedIrreversibleBlockHeights(List<string> specificPublicKeys)
    {
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
        heights.Sort();
        return heights;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-92)
```csharp
        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };

        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-37)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```
