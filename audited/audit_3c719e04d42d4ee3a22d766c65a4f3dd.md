# Audit Report

## Title
Missing Validation Allows Consensus DoS via Zero FinalOrderOfNextRound Values

## Summary
The `ProcessUpdateValue` method accepts arbitrary `SupposedOrderOfNextRound` and `TuneOrderInformation` values without validation, allowing malicious miners to corrupt consensus state with zero values. While `NextRoundMiningOrderValidationProvider` detects this corruption during round transitions, by then the invalid state has been persisted, creating a denial-of-service condition that blocks all future round progressions with no built-in recovery mechanism.

## Finding Description

**Root Cause - Missing Input Validation:**

In `ProcessUpdateValue`, the `SupposedOrderOfNextRound` value from user-controlled `UpdateValueInput` is directly assigned to both `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` fields without any validation that it falls within the valid range [1, minersCount]: [1](#0-0) 

Additionally, the `TuneOrderInformation` dictionary allows any miner to set arbitrary `FinalOrderOfNextRound` values for **any other miner** without access control or range validation: [2](#0-1) 

**Why Existing Validation Fails:**

The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are present and non-empty, and that `PreviousInValue` is correct. It does NOT check `SupposedOrderOfNextRound` or `FinalOrderOfNextRound` values: [3](#0-2) 

This validation gap allows malicious `UpdateValueInput` with zero or invalid order values to pass validation and corrupt state.

**Detection Occurs Too Late:**

The corruption is only detected when `NextRoundMiningOrderValidationProvider` validates the round transition. It checks that the count of miners with `FinalOrderOfNextRound > 0` equals the count of miners with non-null `OutValue`: [4](#0-3) 

However, this validation only runs during `NextRound` behavior, not during `UpdateValue`: [5](#0-4) 

**Expected vs Actual Behavior:**

By design, `ApplyNormalConsensusData` calculates `FinalOrderOfNextRound` as `GetAbsModulus(sigNum, minersCount) + 1`, which guarantees values in the range [1, minersCount]: [6](#0-5) [7](#0-6) 

However, since miners control their `UpdateValueInput` and can modify node software, they can submit arbitrary values that bypass this expected calculation.

**Attack Execution Path:**

1. Malicious miner produces a block with `UpdateValue` transaction
2. Provides `UpdateValueInput` with:
   - `SupposedOrderOfNextRound = 0`
   - `TuneOrderInformation = {"miner1": 0, "miner2": 0, ...}` (setting all other miners to 0)
3. `UpdateValueValidationProvider` validates successfully (doesn't check order values)
4. `ProcessUpdateValue` executes and corrupts state:
   - Sets current miner's `FinalOrderOfNextRound = 0`
   - Iterates through `TuneOrderInformation` and sets all other miners' `FinalOrderOfNextRound = 0`
5. When any miner attempts `NextRound`:
   - `NextRoundMiningOrderValidationProvider` validation fails
   - `distinctCount = 0` (no miners with `FinalOrderOfNextRound > 0`)
   - `count(OutValue != null) > 0` (miners did mine)
   - Validation rejects the `NextRound` transaction
6. Consensus is permanently halted until manual intervention

## Impact Explanation

**Severity: MEDIUM (High Impact, Medium Likelihood)**

**Direct Impact - Complete Consensus Halt:**
- The blockchain cannot progress to the next round once corrupted
- No new blocks can be produced after the current round completes
- All transaction processing stops
- Network participants experience complete service interruption

**Affected Parties:**
- All validators and node operators cannot produce blocks
- All users cannot submit transactions
- All DApps cease to function
- Economic activity on the chain completely stops

**Recovery Difficulty:**
The code provides no built-in recovery mechanism. Once `FinalOrderOfNextRound` values are corrupted to zero in state, there is no contract method to correct them. Recovery requires:
- Manual state intervention by network operators
- Potential hard fork or governance emergency action
- Significant coordination overhead

**Attack Cost:**
- Attacker only needs to be a valid miner in the current round
- Can execute attack by producing a single block with malicious `UpdateValueInput`
- No financial cost beyond normal block production
- Can leverage `TuneOrderInformation` to corrupt all miners' state unilaterally

## Likelihood Explanation

**Overall Likelihood: MEDIUM**

**Feasibility - HIGH:**
- `UpdateValue` is a public method that miners call during normal operation: [8](#0-7) 

- Miners control their node software and can generate arbitrary `UpdateValueInput` structures
- The `UpdateValueInput` structure accepts `supposed_order_of_next_round` and `tune_order_information` as standard fields: [9](#0-8) 

- No cryptographic proofs or complex exploit techniques required
- Single malicious miner can corrupt entire network via `TuneOrderInformation`

**Prerequisites:**
- Attacker must be a current miner (in the active miner set)
- Requires ability to modify node software to generate malicious input
- No collusion required due to `TuneOrderInformation` abuse

**Detection Difficulty:**
- Attack only detected at `NextRound` transition, after state corruption
- No real-time monitoring prevents the malicious `UpdateValue` transaction
- By the time detection occurs, recovery is complex

**Economic Rationality:**
While miners have economic incentives to maintain chain operation, this vulnerability could be exploited for:
- Extortion (threaten to halt chain unless demands met)
- Competitive attacks between mining pools
- Griefing by malicious actors
- Attack cost is minimal (just block production)

## Recommendation

**Immediate Fix - Add Validation in ProcessUpdateValue:**

Add range validation for `SupposedOrderOfNextRound` before assignment:

```csharp
// In ProcessUpdateValue method after line 242
var minersCount = currentRound.RealTimeMinersInformation.Count;
Assert(updateValueInput.SupposedOrderOfNextRound > 0 && 
       updateValueInput.SupposedOrderOfNextRound <= minersCount,
       $"Invalid SupposedOrderOfNextRound. Must be in range [1, {minersCount}]");
```

**Add Access Control for TuneOrderInformation:**

Validate that miners can only tune their own order, or restrict which miners can be tuned:

```csharp
// Before line 259
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
           "Cannot tune order for non-existent miner");
    Assert(tuneOrder.Value > 0 && tuneOrder.Value <= minersCount,
           $"Invalid tuned order. Must be in range [1, {minersCount}]");
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**Enhanced Validation - Add to UpdateValueValidationProvider:**

Include order value validation in the pre-execution validation:

```csharp
// Add to UpdateValueValidationProvider.ValidateHeaderInformation
private bool ValidateOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    
    if (minerInRound.SupposedOrderOfNextRound <= 0 || 
        minerInRound.SupposedOrderOfNextRound > minersCount)
        return false;
        
    if (minerInRound.FinalOrderOfNextRound <= 0 || 
        minerInRound.FinalOrderOfNextRound > minersCount)
        return false;
        
    return true;
}
```

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MaliciousMiner_CanCorruptConsensusState_ViaZeroOrderValues()
{
    // Setup: Initialize consensus with multiple miners
    var initialMiners = GenerateInitialMiners(5);
    await InitializeConsensus(initialMiners);
    
    // Malicious miner is first in the list
    var maliciousMiner = initialMiners[0];
    
    // Create malicious UpdateValueInput with zero order values
    var maliciousInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("valid_outvalue"),
        Signature = HashHelper.ComputeFrom("valid_signature"),
        SupposedOrderOfNextRound = 0, // INVALID: Should be [1, minersCount]
        TuneOrderInformation = // Corrupt all other miners
        {
            { initialMiners[1].Pubkey, 0 },
            { initialMiners[2].Pubkey, 0 },
            { initialMiners[3].Pubkey, 0 },
            { initialMiners[4].Pubkey, 0 }
        },
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        PreviousInValue = Hash.Empty,
        RandomNumber = GenerateRandomNumber()
    };
    
    // Execute: Malicious UpdateValue transaction passes validation
    var result = await AEDPoSContractStub.UpdateValue.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: State is now corrupted
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    foreach (var miner in currentRound.RealTimeMinersInformation.Values)
    {
        // All miners now have FinalOrderOfNextRound = 0
        miner.FinalOrderOfNextRound.ShouldBe(0);
    }
    
    // Attempt NextRound: Should fail due to corrupted state
    var nextRoundInput = GenerateNextRoundInput(currentRound);
    var nextRoundResult = await AEDPoSContractStub.NextRound.SendWithExceptionAsync(nextRoundInput);
    
    // Verify: Consensus is blocked - NextRound validation fails
    nextRoundResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    nextRoundResult.TransactionResult.Error.ShouldContain("Invalid FinalOrderOfNextRound");
    
    // Result: Blockchain cannot progress to next round - DoS achieved
}
```

## Notes

**Key Security Invariant Violated:**
The consensus protocol assumes that `FinalOrderOfNextRound` values are always in the valid range [1, minersCount] and that miners who produced blocks have positive order values for the next round. This invariant is broken by accepting arbitrary user input without validation.

**Why This Is Not Caught Earlier:**
The validation architecture uses different providers for different behaviors. `UpdateValueValidationProvider` focuses on cryptographic validation (signatures, previous values) but doesn't validate consensus state consistency. `NextRoundMiningOrderValidationProvider` validates state consistency but only runs during round transitions, making it a fail-safe rather than a preventive measure.

**Single Point of Failure:**
The `TuneOrderInformation` mechanism is particularly dangerous because it allows a single miner to corrupt the `FinalOrderOfNextRound` values of **all other miners** without any access control or validation. This turns what could require collusion into a unilateral attack vector.

**Recovery Complexity:**
Unlike other consensus issues that self-heal in subsequent rounds, this attack permanently corrupts state that prevents round progression. The only recovery paths are manual state intervention or emergency governance actions, both of which require significant coordination and may not be possible without predetermined recovery procedures.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** protobuf/aedpos_contract.proto (L206-208)
```text
    int32 supposed_order_of_next_round = 6;
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
```
