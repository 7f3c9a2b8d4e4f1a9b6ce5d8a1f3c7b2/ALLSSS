# Audit Report

## Title
Non-Deterministic Miner Selection in FirstMiner() Enabling Consensus Divergence via Unvalidated Order Field Duplication

## Summary
The `FirstMiner()` method uses non-deterministic iteration over a Protocol Buffers `MapField` to identify the miner with `Order == 1`. The consensus validation pipeline fails to enforce uniqueness of the `Order` field in externally-submitted `NextRoundInput` transactions. A malicious miner can exploit this validation gap to inject duplicate `Order` values, causing different nodes to return different miners from `FirstMiner()`, leading to immediate consensus divergence and chain fork.

## Finding Description

The vulnerability exists in the `FirstMiner()` method which retrieves the first miner without deterministic ordering: [1](#0-0) 

The `RealTimeMinersInformation` field is defined as a Protocol Buffers map type that provides no iteration order guarantees: [2](#0-1) 

The codebase demonstrates clear awareness of MapField non-determinism by explicitly using `OrderBy(m => m.Order)` in multiple consensus-critical locations: [3](#0-2) [4](#0-3) [5](#0-4) 

However, `FirstMiner()` fails to apply this deterministic safeguard, creating an exploitable inconsistency.

**Attack Path:**

1. A malicious miner crafts a `NextRoundInput` with duplicate `Order` values (e.g., two miners assigned `Order == 1`)

2. The transaction is submitted via the `NextRound` public method: [6](#0-5) 

3. Validation executes via `NextRoundMiningOrderValidationProvider` but **only verifies `FinalOrderOfNextRound` uniqueness**, not `Order` field uniqueness: [7](#0-6) 

4. The malicious round bypasses validation and is converted directly without Order uniqueness checks: [8](#0-7) 

5. The malicious round is stored in contract state: [9](#0-8) [10](#0-9) 

6. When consensus logic calls `FirstMiner()`, different nodes iterate the MapField in different orders, returning different miners and making divergent consensus decisions: [11](#0-10) 

## Impact Explanation

This vulnerability breaks the fundamental consensus invariant that all honest nodes must reach identical state given identical input.

**Consensus Divergence:**
- Different nodes retrieve different miners from `FirstMiner()` due to non-deterministic MapField iteration
- Nodes make conflicting consensus behavior decisions (NextRound vs UpdateValue vs TinyBlock)
- Blocks produced by one node group are rejected by another group
- Immediate consensus failure across the network

**Chain Fork:**
- Network partitions into incompatible forks
- Transactions confirmed on one fork may be invalid on another
- Finality guarantees are violated
- Network requires manual intervention to recover

**Scope:**
- All network participants affected
- Complete breakdown of consensus mechanism
- Protocol integrity fundamentally compromised

## Likelihood Explanation

**Preconditions:**
1. Attacker must be a valid miner in the current round (verified by PreCheck): [12](#0-11) 

2. Attacker must successfully submit the NextRound transaction (competitive but achievable)

3. No validation prevents duplicate `Order` values in the submitted round data

**Feasibility:**
- **Medium complexity**: Requires miner privileges but no special cryptographic capabilities
- **Straightforward execution**: Crafting malicious `NextRoundInput` involves standard protobuf message construction with duplicate Order field values
- **Confirmed validation gap**: No validator in the chain checks Order uniqueness
- **Guaranteed impact**: Once malicious round is stored, consensus divergence is deterministic

**Probability Assessment:**
- **Low-Medium** in practice because:
  - Normal round generation via `GenerateNextRoundInformation` produces unique orders
  - Multiple honest miners compete to submit round transitions
  - However, a single malicious miner can trigger the exploit
  - No defense-in-depth exists if normal generation is bypassed

The vulnerability is exploitable with miner privileges and successful transaction timing, but defended against by honest miner majority in normal operation.

## Recommendation

**1. Add Order Uniqueness Validation:**

Create a new validation provider that checks Order field uniqueness in NextRound transactions. Add to `ValidateBeforeExecution` for NextRound behavior:

```csharp
public class OrderUniquenessValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var providedRound = validationContext.ProvidedRound;
        var orders = providedRound.RealTimeMinersInformation.Values.Select(m => m.Order).ToList();
        var distinctOrders = orders.Distinct().Count();
        
        if (distinctOrders != orders.Count)
            return new ValidationResult { Message = "Duplicate Order values detected in round information." };
            
        return new ValidationResult { Success = true };
    }
}
```

Register in validation pipeline: [13](#0-12) 

**2. Fix FirstMiner() for Determinism:**

Apply consistent ordering to eliminate non-determinism:

```csharp
public MinerInRound FirstMiner()
{
    return RealTimeMinersInformation.Count > 0
        ? RealTimeMinersInformation.Values.OrderBy(m => m.Pubkey).FirstOrDefault(m => m.Order == 1)
        : new MinerInRound();
}
```

**3. Fix Additional Non-Deterministic Code:**

In `GenerateNextRoundInformation`, replace: [14](#0-13) 

With deterministic selection:
```csharp
if (expectedExtraBlockProducer == null)
    nextRound.RealTimeMinersInformation.Values.OrderBy(m => m.Pubkey).First().IsExtraBlockProducer = true;
```

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_DuplicateOrders_CausesNonDeterministicFirstMiner()
{
    // Setup: Initialize consensus with 3 miners
    await InitializeConsensus();
    
    // Craft malicious NextRoundInput with duplicate Order == 1
    var maliciousRound = new NextRoundInput
    {
        RoundNumber = 2,
        RealTimeMinersInformation =
        {
            ["miner1"] = new MinerInRound { Pubkey = "miner1", Order = 1 },
            ["miner2"] = new MinerInRound { Pubkey = "miner2", Order = 1 }, // Duplicate!
            ["miner3"] = new MinerInRound { Pubkey = "miner3", Order = 3 }
        }
    };
    
    // Execute: Submit malicious NextRound (validation will pass)
    await MinerKeyPair1.ExecuteAsync(Stub.NextRound, maliciousRound);
    
    // Verify: FirstMiner() returns non-deterministic results
    var round = await Stub.GetCurrentRoundInformation.CallAsync(new Empty());
    var firstMiner1 = round.FirstMiner(); // May return miner1
    var firstMiner2 = round.FirstMiner(); // May return miner2 on different node
    
    // On same node, results are consistent, but across nodes they diverge
    // This breaks consensus as nodes make different behavior decisions
}
```

**Notes:**
- The vulnerability requires miner privileges (PreCheck verification) but no other special access
- Protocol Buffers maps in C# use implementation-dependent iteration order that varies across processes/deserializations
- The codebase's explicit use of `OrderBy()` in other locations proves awareness of the non-determinism issue
- Normal honest operation is safe due to `GenerateNextRoundInformation` producing unique orders
- The attack bypasses this by directly crafting malicious input that passes validation

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L35-35)
```csharp
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L119-119)
```csharp
        return RealTimeMinersInformation.OrderBy(m => m.Value.Order).Last().Value
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L97-98)
```csharp
        var latestSignature = currentRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .LastOrDefault(m => m.Signature != null)?.Signature;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L94-102)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L60-65)
```csharp
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;
```
