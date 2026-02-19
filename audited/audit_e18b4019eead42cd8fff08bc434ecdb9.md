# Audit Report

## Title
Missing Validation Allows Negative LIB Height Injection via NextTerm Transaction

## Summary
A malicious miner can permanently corrupt the consensus state by injecting a negative `ConfirmedIrreversibleBlockHeight` value during term transitions. The `NextTerm` transaction validation only checks round and term numbers, completely omitting the LIB height validation that protects other consensus behaviors, allowing corrupted values to persist indefinitely and propagate through all future rounds.

## Finding Description

The vulnerability exists in the consensus validation logic where different validation providers are applied based on the consensus behavior type. The critical security gap is that `LibInformationValidationProvider` is only applied to `UpdateValue` behavior but not to `NextTerm` behavior.

**Attack Flow:**

1. A malicious miner with a valid time slot during a term transition crafts a custom `NextTermInput` with `ConfirmedIrreversibleBlockHeight = -1` (or any negative/invalid value).

2. When `NextTerm()` is called, it invokes `ProcessConsensusInformation()` which performs validation via `ValidateBeforeExecution()`. [1](#0-0) 

3. For `NextTerm` behavior, the validation logic ONLY adds `RoundTerminateValidationProvider`, omitting the critical `LibInformationValidationProvider`: [2](#0-1) 

4. The `RoundTerminateValidationProvider` validates ONLY round number and term number increments, completely ignoring LIB height fields: [3](#0-2) 

5. In contrast, `UpdateValue` behavior correctly includes `LibInformationValidationProvider` which validates that LIB height cannot decrease: [4](#0-3) 

6. The `LibInformationValidationProvider` that would prevent this attack checks both `ConfirmedIrreversibleBlockHeight` and `ImpliedIrreversibleBlockHeight` cannot decrease: [5](#0-4) 

7. After passing validation, `ProcessNextTerm()` converts the malicious input to a `Round` object via `ToRound()`, which preserves all fields including the corrupted `ConfirmedIrreversibleBlockHeight`: [6](#0-5) 

8. This corrupted Round is stored directly in state: [7](#0-6) 

9. The corrupted value propagates to all subsequent rounds because `GenerateFirstRoundOfNewTerm()` unconditionally copies the `ConfirmedIrreversibleBlockHeight` from the current round: [8](#0-7) 

**Why Normal Protections Fail:**

Normal `UpdateValue` transactions correctly calculate LIB height and filter non-positive `ImpliedIrreversibleBlockHeight` values during processing. However, `NextTerm` transactions bypass this calculation entirely by accepting the LIB value directly from the input parameter without any validation. The validation framework inconsistency creates an exploitable gap where a fundamental consensus invariant (LIB height monotonicity) is enforced for one behavior but not another.

## Impact Explanation

**Critical Consensus Corruption:**

A negative `ConfirmedIrreversibleBlockHeight` value breaks the fundamental blockchain invariant that LIB height represents the highest irreversible block. This corruption has cascading effects:

1. **Broken Finality Tracking**: The LIB height is used throughout the system to determine which blocks are considered final. A negative value invalidates all finality guarantees.

2. **Persistent State Corruption**: The corrupted value is stored in `State.Rounds` and propagates to every subsequent round and term through the copy operations in round generation logic. Once injected, it persists indefinitely without manual intervention.

3. **Cross-Chain Security Failures**: Cross-chain indexing and relay contracts depend on `ConfirmedIrreversibleBlockHeight` to determine which blocks are safe to index. Negative values could cause integer underflows, validation bypasses, or complete cross-chain bridge halts.

4. **Block Production Impact**: Future round generation inherits the corrupted value, potentially causing arithmetic errors or validation failures in time slot calculations and miner scheduling.

**Severity: CRITICAL** - A single malicious miner can permanently corrupt core consensus state, breaking fundamental blockchain invariants and requiring emergency intervention (hard fork or chain rollback) to recover.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be an active miner (one of ~20+ validators)
- Attacker must wait for their turn during a term transition (occurs every few days)
- Attacker must run modified node software to craft malicious `NextTermInput`

**Execution Complexity: LOW**
- Single transaction during legitimate mining slot
- No race conditions or timing dependencies
- No need to compromise other miners or governance mechanisms
- Validation deterministically passes due to missing checks
- Direct state manipulation via public contract method

**Feasibility: HIGH**
The `NextTerm` method is public and callable by any miner during their authorized time slot. [9](#0-8)  The only permission check verifies the sender is in the miner list, which the attacker legitimately satisfies.

**Detection:** The attack is immediately visible in consensus state once executed, but the damage is already done as the corrupted value is permanently stored and begins propagating.

**Overall Likelihood: HIGH** - Any active miner can execute this attack during any term transition with guaranteed success if they reach their NextTerm time slot.

## Recommendation

Add `LibInformationValidationProvider` to the validation providers for `NextTerm` behavior to ensure LIB height consistency is enforced across all consensus behaviors:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
```

This ensures that the same LIB height monotonicity validation applied to `UpdateValue` transactions is also applied to `NextTerm` transactions, preventing negative or decreasing LIB height values from being injected into consensus state.

Additionally, consider adding explicit validation in `ProcessNextTerm()` to verify that `ConfirmedIrreversibleBlockHeight` is non-negative and not less than the previous round's value before storing the new round.

## Proof of Concept

```csharp
[Fact]
public async Task NextTerm_Should_Reject_Negative_LIB_Height()
{
    // Setup: Initialize consensus with first round
    var initialMiners = GenerateMinerList(3);
    var initialRound = GenerateFirstRound(initialMiners);
    await InitializeConsensus(initialRound);
    
    // Progress to near end of term
    await ProduceBlocksUntilTermEnd();
    
    // Get current round with valid LIB height
    var currentRound = await GetCurrentRoundInformation();
    Assert.True(currentRound.ConfirmedIrreversibleBlockHeight > 0);
    
    // Malicious miner crafts NextTermInput with negative LIB height
    var maliciousNextTermInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber + 1,
        ConfirmedIrreversibleBlockHeight = -1, // Malicious negative value
        ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber,
        RealTimeMinersInformation = { GenerateNextTermMiners() },
        RandomNumber = ByteString.CopyFrom(GenerateRandomBytes())
    };
    
    // Attack: Call NextTerm with malicious input
    var result = await ConsensusStub.NextTerm.SendAsync(maliciousNextTermInput);
    
    // Currently PASSES due to missing validation (vulnerability)
    // Should FAIL with "Incorrect lib information" error
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Failed);
    Assert.Contains("lib information", result.TransactionResult.Error);
    
    // Verify LIB height was NOT corrupted
    var newRound = await GetCurrentRoundInformation();
    Assert.True(newRound.ConfirmedIrreversibleBlockHeight > 0);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-28)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L196-196)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-20)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L51-52)
```csharp
        round.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        round.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-17)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
```
