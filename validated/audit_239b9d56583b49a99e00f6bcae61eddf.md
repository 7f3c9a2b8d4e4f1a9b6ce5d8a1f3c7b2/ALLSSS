# Audit Report

## Title
Missing Range Validation on Mining Orders Allows Consensus DoS via Invalid Order Assignment

## Summary
The AEDPoS consensus contract lacks range validation for `FinalOrderOfNextRound` values when miners submit `UpdateValue` transactions. A malicious miner can inject out-of-range order values (e.g., 100, 101) that bypass validation, corrupt the consensus state, and cause complete blockchain halt when the next round attempts to generate.

## Finding Description

The vulnerability exists across multiple validation layers that each fail to prevent out-of-range mining order assignments:

**Root Cause - Insufficient Validation Logic:**

The `NextRoundMiningOrderValidationProvider` only performs a count-based check without validating actual order values or ranges [1](#0-0) . This validation confirms the count of distinct orders matches miners who produced blocks, but critically fails to verify orders are within [1, minersCount] or sequential without gaps.

**Attack Vector - Unvalidated Order Injection:**

Miners can inject arbitrary orders through `UpdateValue`, which is a public RPC method [2](#0-1) [3](#0-2) .

The `UpdateValueInput` accepts a `tune_order_information` map allowing arbitrary miner-to-order assignments [4](#0-3) .

When `ProcessUpdateValue` executes, it blindly applies these values to state without any validation [5](#0-4) .

**Why Existing Protections Fail:**

1. The validation service only uses `UpdateValueValidationProvider` for `UpdateValue` behavior, which does NOT validate `tune_order_information` ranges [6](#0-5) .

2. `NextRoundMiningOrderValidationProvider` is ONLY invoked for `NextRound` behavior, NOT for `UpdateValue` [7](#0-6) .

**Exploitation Path - Consensus Failure:**

When `GenerateNextRoundInformation` uses corrupted `FinalOrderOfNextRound` values, it directly assigns them as `Order` in the next round [8](#0-7) .

This causes immediate failures in critical consensus operations:

- `BreakContinuousMining` assumes Order 1 exists and throws `InvalidOperationException` when calling `First(i => i.Order == 1)` [9](#0-8) .

- Similarly fails for Order 2 [10](#0-9) .

- `GetMiningInterval` fails when no miners have Order 1 or 2, throwing `ArgumentOutOfRangeException` when accessing array indices [11](#0-10) .

- `FirstMiner()` returns null when Order 1 doesn't exist, breaking time calculations [12](#0-11) .

## Impact Explanation

**Severity: HIGH - Complete Consensus System Failure**

This vulnerability causes catastrophic blockchain failure:

1. **Network-Wide Halt**: Once corrupted orders are applied, ALL miners attempting to produce the next round will encounter exceptions in `GenerateNextRoundInformation`, `BreakContinuousMining`, or `GetMiningInterval`, preventing any new blocks from being produced.

2. **Irrecoverable State**: The consensus state is persisted with invalid orders. The blockchain cannot self-heal - it requires hard fork or manual state intervention to recover.

3. **Complete DoS**: While no funds are stolen, the entire blockchain becomes non-operational, halting all transactions, smart contract executions, and token transfers.

4. **Production Impact**: This affects mainnet operations where consensus integrity is critical for business continuity.

The impact qualifies as HIGH severity because it breaks a fundamental protocol invariant (consensus availability) affecting the entire network's ability to produce blocks.

## Likelihood Explanation

**Probability: HIGH - Low Barrier to Execution**

The attack has minimal prerequisites and high feasibility:

**Attacker Capabilities:**
- Any miner in the current mining schedule can execute this attack [13](#0-12) 
- No special permissions required beyond being an active validator
- Single malicious block with crafted consensus data is sufficient

**Attack Complexity:**
- LOW: Miner produces block with `UpdateValue` transaction containing out-of-range `tune_order_information`
- Example payload: `{"miner1": 100, "miner2": 101, "miner3": 1, "miner4": 2}`
- No cryptographic breaks or complex exploitation required

**Feasibility:**
- Miners control the blocks they produce and consensus data included
- No economic cost beyond standard transaction fees
- Validation gaps ensure the malicious transaction passes all checks
- Immediate effect once block is accepted

The combination of low complexity, minimal prerequisites, and guaranteed success makes this HIGH likelihood.

## Recommendation

Add range validation for `TuneOrderInformation` values in `ProcessUpdateValue`:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    
    // Validate tune order information ranges
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
            $"Invalid order value: {tuneOrder.Value}. Must be between 1 and {minersCount}.");
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
            $"Invalid miner pubkey in tune order information: {tuneOrder.Key}");
    }
    
    // Validate no duplicate orders
    var tuneOrderValues = updateValueInput.TuneOrderInformation.Values.ToList();
    Assert(tuneOrderValues.Count == tuneOrderValues.Distinct().Count(),
        "Duplicate order values in tune order information.");
    
    // Continue with existing logic...
}
```

Additionally, enhance `NextRoundMiningOrderValidationProvider` to validate order ranges and check for gaps.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanCorruptConsensusWithInvalidOrders_CausingBlockchainHalt()
{
    // Setup: Initialize consensus with 5 miners
    var miners = GenerateMiners(5);
    await InitializeConsensusContract(miners);
    
    // Malicious miner creates UpdateValueInput with out-of-range orders
    var maliciousMiner = miners[0];
    var maliciousInput = new UpdateValueInput
    {
        OutValue = GenerateHash(),
        Signature = GenerateHash(),
        RoundId = 1,
        ActualMiningTime = Timestamp.FromDateTime(DateTime.UtcNow),
        SupposedOrderOfNextRound = 1,
        TuneOrderInformation = 
        {
            { miners[0].ToHex(), 100 },  // Invalid: out of range
            { miners[1].ToHex(), 101 },  // Invalid: out of range
            { miners[2].ToHex(), 102 },  // Invalid: out of range
        },
        RandomNumber = ByteString.Empty
    };
    
    // Execute: Malicious UpdateValue passes validation
    var result = await ConsensusStub.UpdateValue.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: State is corrupted with invalid orders
    var round = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    round.RealTimeMinersInformation[miners[0].ToHex()].FinalOrderOfNextRound.ShouldBe(100);
    
    // Attempt: Next round generation fails with exception
    await Assert.ThrowsAsync<InvalidOperationException>(async () => 
    {
        await GenerateNextRound(); // This will fail in BreakContinuousMining
    });
    
    // Result: Blockchain is halted, no new blocks can be produced
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
```

**File:** protobuf/aedpos_contract.proto (L30-31)
```text
    rpc UpdateValue (UpdateValueInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-87)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-32)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-79)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L83-84)
```csharp
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L76-80)
```csharp
        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L144-145)
```csharp
        return RealTimeMinersInformation.Count > 0
            ? RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == 1)
```
