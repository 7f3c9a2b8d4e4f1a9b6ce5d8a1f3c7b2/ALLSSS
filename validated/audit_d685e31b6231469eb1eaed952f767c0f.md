# Audit Report

## Title
Non-Deterministic Miner Selection in FirstMiner() Due to MapField Iteration Order Dependency

## Summary
The `FirstMiner()` method uses non-deterministic Protocol Buffers `MapField` iteration without explicit ordering to identify the miner with `Order == 1`. The consensus validation pipeline does not enforce uniqueness of the `Order` field in externally-submitted `NextRoundInput` transactions. When duplicate Order values exist, different nodes return different miners from `FirstMiner()`, causing immediate consensus divergence and chain fork.

## Finding Description

The vulnerability exists in the `FirstMiner()` method, which uses `FirstOrDefault()` on a MapField without deterministic ordering: [1](#0-0) 

The `RealTimeMinersInformation` field is a Protocol Buffers map type that does not guarantee deterministic iteration order across different nodes or implementations.

**Critical Usage in Consensus Logic:**

The `FirstMiner()` method is called in consensus behavior determination code: [2](#0-1) 

This determines whether a miner should produce a NextRound, UpdateValue, or TinyBlock. If `FirstMiner()` returns different results on different nodes, they will make incompatible consensus decisions.

**Attack Path:**

1. A malicious miner crafts a `NextRoundInput` with duplicate `Order` values (e.g., two miners both assigned `Order == 1`)
2. The attacker submits this via the `NextRound` transaction
3. The transaction passes `PreCheck()` which only verifies the sender is in the miner list: [3](#0-2) 

4. Validation executes but **only checks `FinalOrderOfNextRound` uniqueness**, not `Order` uniqueness: [4](#0-3) 

5. The malicious Round is directly converted from input without Order validation: [5](#0-4) [6](#0-5) 

6. When consensus logic subsequently calls `FirstMiner()`, different nodes iterate the MapField in different orders, returning different miners
7. Nodes make different consensus decisions, causing immediate consensus failure

**Additional Non-Deterministic Code:**

The `GenerateNextRoundInformation` method contains another non-deterministic operation: [7](#0-6) 

Line 63 uses `.First()` without any ordering on the MapField, which also returns non-deterministic results across nodes if `expectedExtraBlockProducer` is null.

## Impact Explanation

This vulnerability breaks the fundamental blockchain invariant: **all honest nodes must reach identical state given identical input**.

**Consensus Failure:**
- Different nodes return different miners from `FirstMiner()` due to non-deterministic MapField iteration
- Nodes make incompatible consensus decisions (NextRound vs UpdateValue vs TinyBlock behavior)
- Blocks produced by one partition are rejected by another partition
- Immediate and total consensus failure

**Chain Fork:**
- Network splits into incompatible partitions based on MapField iteration order
- Transactions may be confirmed on one fork but rejected on another
- Finality guarantees are completely violated
- Network halts and requires manual intervention to resolve

**Affected Parties:**
- All network participants experience consensus failure
- Users cannot reliably transact
- Core protocol integrity is compromised
- Requires emergency response and potential rollback

This is a **critical severity** consensus break that affects the entire network.

## Likelihood Explanation

**Preconditions:**
1. Attacker must be a valid miner in the current round (verified in `PreCheck`)
2. Attacker must successfully submit the NextRound transaction (competitive timing with other miners)
3. No code validation prevents duplicate `Order` values in the input

**Feasibility:**
- **Medium complexity** - requires active miner privileges but no special cryptographic knowledge
- Crafting malicious `NextRoundInput` is straightforward (standard protobuf message construction)
- Validation gap is confirmed - `NextRoundMiningOrderValidationProvider` only checks `FinalOrderOfNextRound`, not `Order`
- If successful, consensus divergence is **guaranteed** (deterministic outcome from non-deterministic input)

**Probability:**
- **Low-Medium** in practice:
  - Normal round generation via `GenerateNextRoundInformation` produces unique orders
  - Multiple honest miners compete to submit round transitions
  - However, a single malicious miner with proper timing can trigger the exploit
  - No defense-in-depth mechanisms exist
  - The validation gap is exploitable by any current miner

The vulnerability requires miner-level privileges and successful transaction submission timing, but provides guaranteed consensus break if executed.

## Recommendation

**Fix 1: Add Order Uniqueness Validation**

Add validation in `NextRoundMiningOrderValidationProvider` or create a dedicated provider that checks Order uniqueness:

```csharp
var orderValues = providedRound.RealTimeMinersInformation.Values.Select(m => m.Order).ToList();
if (orderValues.Count != orderValues.Distinct().Count())
{
    validationResult.Message = "Duplicate Order values detected.";
    return validationResult;
}
```

**Fix 2: Make FirstMiner() Deterministic**

Replace non-deterministic `FirstOrDefault` with explicit ordering:

```csharp
public MinerInRound FirstMiner()
{
    return RealTimeMinersInformation.Count > 0
        ? RealTimeMinersInformation.OrderBy(kvp => kvp.Key).Select(kvp => kvp.Value).FirstOrDefault(m => m.Order == 1)
        : new MinerInRound();
}
```

**Fix 3: Fix GenerateNextRoundInformation Line 63**

Replace non-deterministic `.First()` with explicit ordering:

```csharp
if (expectedExtraBlockProducer == null)
    nextRound.RealTimeMinersInformation.OrderBy(kvp => kvp.Key).First().Value.IsExtraBlockProducer = true;
```

**Comprehensive Fix:**

All MapField iterations in consensus-critical code paths should use explicit ordering (e.g., `OrderBy(kvp => kvp.Key)`) to ensure deterministic behavior across all nodes.

## Proof of Concept

A proof of concept would require:
1. Setting up a test network with multiple nodes
2. A malicious miner crafting a `NextRoundInput` with duplicate Order values (e.g., two miners with Order == 1)
3. Submitting the transaction via `NextRound()`
4. Observing that different nodes return different results from `FirstMiner()`
5. Demonstrating that nodes make different consensus decisions and the network forks

The vulnerability is demonstrated by:
- Code analysis showing no Order uniqueness validation exists
- `FirstMiner()` using non-deterministic MapField iteration
- Critical consensus logic depending on `FirstMiner()` results
- Direct path from miner-submitted input to stored Round data without validation

## Notes

The codebase shows awareness of MapField non-determinism by using `OrderBy()` in other locations (e.g., line 35 in `Round.cs`), but critically fails to apply this safeguard in `FirstMiner()` and in `GenerateNextRoundInformation` line 63. This represents a systematic validation gap that allows externally-controlled data with duplicate Order values to bypass all checks and directly cause consensus divergence.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-111)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-66)
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
