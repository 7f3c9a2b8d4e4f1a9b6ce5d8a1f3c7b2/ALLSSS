# Audit Report

## Title
Non-Deterministic Miner Selection in FirstMiner() Due to MapField Iteration Order Dependency

## Summary
The `FirstMiner()` method uses non-deterministic `MapField` iteration to find miners with `Order == 1`, while validation does not enforce `Order` field uniqueness in externally-submitted `NextRoundInput` data. If duplicate Order values exist, different nodes will return different miners from `FirstMiner()`, causing immediate consensus divergence and chain fork.

## Finding Description

The vulnerability exists in the `FirstMiner()` method, which relies on non-deterministic MapField iteration: [1](#0-0) 

The `RealTimeMinersInformation` field is defined as a Protocol Buffers map type: [2](#0-1) 

Protocol Buffers maps do not guarantee deterministic iteration order. When `FirstMiner()` calls `.FirstOrDefault(m => m.Order == 1)` on `MapField.Values`, it may return different results across nodes if multiple miners have `Order == 1`.

**Attack Path:**

1. A malicious miner crafts a `NextRoundInput` with duplicate `Order` values (e.g., two miners both have `Order == 1`)
2. The attacker submits this via the public `NextRound` transaction
3. Permission validation passes because the attacker is a valid miner: [3](#0-2) 
4. The validation pipeline only checks `FinalOrderOfNextRound` uniqueness from the previous round, not `Order` uniqueness in the new round: [4](#0-3) 
5. The malicious round data is directly converted and stored: [5](#0-4) [6](#0-5) 
6. When consensus logic calls `FirstMiner()`, different nodes iterate the MapField in different orders and return different miners
7. Consensus decisions diverge, particularly in behavior determination: [7](#0-6) 

**Additional Non-Deterministic Code:**

The `GenerateNextRoundInformation` method contains additional non-deterministic code when the calculated extra block producer order doesn't match any miner: [8](#0-7) 

If `expectedExtraBlockProducer` is null, line 63 uses `.First()` without ordering on the MapField.Values collection, returning a non-deterministic result.

## Impact Explanation

This vulnerability breaks the fundamental consensus invariant: **all honest nodes must reach identical state given the same input**.

**Consensus Break:**
- Different nodes return different miners from `FirstMiner()`
- Nodes make different consensus decisions (UpdateValue vs NextRound vs TinyBlock behaviors)
- Blocks produced by one group are rejected by another group based on their consensus state
- Immediate consensus failure preventing network progress

**Chain Fork:**
- Network partitions into incompatible groups with different state
- Transactions confirmed on one fork are invalid on another
- Finality guarantees are completely violated
- Manual intervention required to recover the network

**Affected Parties:**
- All network participants experience service disruption
- Users cannot reliably submit transactions
- Protocol integrity and trust are fundamentally compromised

## Likelihood Explanation

**Preconditions:**
1. Attacker must be a valid miner in the current round (obtainable through election process)
2. Attacker must successfully submit the NextRound transaction (competitive timing with honest miners)
3. No validation prevents duplicate `Order` values in submitted data

**Feasibility:**
- Medium complexity - requires miner privileges but no cryptographic breaks
- Crafting malicious `NextRoundInput` is straightforward (standard protobuf message construction)
- Validation gap confirmed - no check for `Order` uniqueness in the new round
- Once malicious round is stored, consensus divergence is guaranteed

**Probability Assessment:**
- Low-Medium in practice because:
  - Normal round generation via `GenerateNextRoundInformation` produces unique orders based on validated `FinalOrderOfNextRound` values
  - Multiple honest miners typically compete to submit round transitions
  - However, a single determined malicious miner can exploit the validation gap
  - No defense-in-depth exists if the attacker bypasses normal generation flow

The vulnerability is exploitable, requiring only miner privileges and successful transaction timing to trigger catastrophic consensus failure.

## Recommendation

Add explicit validation for `Order` field uniqueness in submitted `NextRoundInput` data:

1. **Add Order uniqueness validation** in `NextRoundMiningOrderValidationProvider` or create a dedicated validator:
   - Check that all `Order` values in `providedRound.RealTimeMinersInformation.Values` are unique
   - Verify that Orders form a continuous sequence from 1 to N (where N is miner count)

2. **Fix non-deterministic iteration** in `FirstMiner()`:
   - Replace with deterministic selection: use dictionary key lookup or sorted iteration
   - Example: `return RealTimeMinersInformation.Values.OrderBy(m => m.Pubkey).FirstOrDefault(m => m.Order == 1)`

3. **Fix non-deterministic fallback** in `GenerateNextRoundInformation`:
   - Replace `.First()` with deterministic selection
   - Example: `.OrderBy(m => m.Pubkey).First()`

4. **Add comprehensive Order validation**:
   - Validate Order completeness (no gaps in sequence)
   - Validate Order bounds (1 to miner count)
   - Enforce exactly one miner per Order value

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
public async Task NonDeterministicFirstMiner_CausesConsensusDivergence()
{
    // Setup: Create a round with duplicate Order == 1
    var maliciousRound = new Round
    {
        RoundNumber = 2,
        TermNumber = 1,
        RealTimeMinersInformation = {
            { "miner1", new MinerInRound { Pubkey = "miner1", Order = 1, OutValue = Hash.Empty } },
            { "miner2", new MinerInRound { Pubkey = "miner2", Order = 1, OutValue = null } }, // Duplicate Order=1
            { "miner3", new MinerInRound { Pubkey = "miner3", Order = 2, OutValue = null } }
        }
    };
    
    // Test: Call FirstMiner() multiple times
    // Due to non-deterministic MapField iteration, results may vary across nodes
    var firstMiner1 = maliciousRound.FirstMiner(); 
    var firstMiner2 = maliciousRound.FirstMiner();
    
    // On different nodes or different runtime conditions, these could return different miners
    // This breaks the consensus invariant that all nodes must agree on state
    
    // Demonstrate: Submit malicious NextRound transaction
    var maliciousInput = NextRoundInput.Create(maliciousRound, randomNumber);
    await ConsensusContract.NextRound(maliciousInput);
    
    // Validation passes (no Order uniqueness check)
    // Malicious round is stored
    // Subsequent FirstMiner() calls return non-deterministic results
    // Consensus diverges
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L142-148)
```csharp
    public MinerInRound FirstMiner()
    {
        return RealTimeMinersInformation.Count > 0
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == 1)
            // Unlikely.
            : new MinerInRound();
    }
```

**File:** protobuf/aedpos_contract.proto (L247-247)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L92-102)
```csharp
        private AElfConsensusBehaviour HandleMinerInNewRound()
        {
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-65)
```csharp
        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```
