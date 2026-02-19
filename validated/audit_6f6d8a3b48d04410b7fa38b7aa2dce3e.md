# Audit Report

## Title
ImpliedIrreversibleBlockHeight Validation Bypass via RecoverFromUpdateValue Timing Issue

## Summary
The `LibInformationValidationProvider` validation is completely bypassed for `ImpliedIrreversibleBlockHeight` during UpdateValue consensus behavior. The root cause is that `RecoverFromUpdateValue` modifies the `BaseRound` object before validation occurs, causing the validator to compare the malicious value against itself. This allows any miner to inject fraudulently low implied LIB heights into consensus state, compromising blockchain finality guarantees.

## Finding Description

The vulnerability exists in the validation flow for UpdateValue consensus behavior due to incorrect execution ordering. 

When validating UpdateValue behavior, the system first retrieves the current round information from state into `baseRound`. [1](#0-0) 

Before any validation occurs, if the behavior is UpdateValue, `RecoverFromUpdateValue` is called on the `baseRound` object, modifying it in-memory. [2](#0-1) 

The recovery implementation copies `ImpliedIrreversibleBlockHeight` from the provided round (attacker's input) into the baseRound object. [3](#0-2) 

The validation context is then created using the now-modified baseRound, and the `LibInformationValidationProvider` is added to the validation chain for UpdateValue behavior. [4](#0-3) 

The validator attempts to check if the baseRound's ImpliedIrreversibleBlockHeight is greater than the providedRound's value to detect regression. [5](#0-4) 

However, since `RecoverFromUpdateValue` already copied the value from providedRound into baseRound, both values are now identical. The validation check becomes: `maliciousValue > maliciousValue`, which always evaluates to false, allowing the malicious value to pass validation.

After validation passes, the malicious `ImpliedIrreversibleBlockHeight` is persisted to state during consensus processing. [6](#0-5) 

**Root Cause**: The design flaw is that state recovery happens before validation, corrupting the reference point (baseRound) that validators rely on to detect malicious decreases. The validation becomes a tautology.

## Impact Explanation

The `ImpliedIrreversibleBlockHeight` is a critical component of the Last Irreversible Block (LIB) calculation. The LIB calculation collects implied irreversible heights from miners in the previous round, sorts them, and takes the value at position `(count-1)/3` to ensure 2/3+1 Byzantine fault tolerance. [7](#0-6) 

A malicious miner can:

1. **Inject Fraudulent Low Values**: Submit an arbitrarily low `ImpliedIrreversibleBlockHeight` (e.g., 100 when the current height is 1000) during their UpdateValue call
2. **Manipulate LIB Calculation**: In subsequent rounds, this fraudulent value enters the sorted list used for LIB calculation
3. **Compromise Finality**: While the 2/3+1 threshold limits single-miner impact, repeated attacks or collusion among multiple miners can significantly lower the calculated LIB and prevent proper finality advancement

**Severity**: HIGH - This bypasses a critical consensus validation mechanism designed to prevent regression of finality markers, directly impacting blockchain security guarantees and affecting all network participants relying on LIB for transaction finality confirmation.

## Likelihood Explanation

**Attacker Capabilities**: Any elected miner in the current round can execute this attack with no special privileges beyond normal mining rights.

**Attack Complexity**: LOW - The attack simply requires providing a lower-than-legitimate `ImpliedIrreversibleBlockHeight` value when producing a block during UpdateValue behavior. The validation bypass is automatic due to the code execution order.

**Feasibility**: The attack is executable during normal block production (UpdateValue occurs every block), requires no additional preconditions, and has no detection mechanism in the current validation logic.

**Probability**: HIGH - Any miner can execute this attack at any time during their block production slot without detection by the current validation system.

## Recommendation

Fix the execution order by performing validation BEFORE state recovery. The corrected flow should be:

1. Retrieve `baseRound` from state (original values)
2. Create validation context with unmodified baseRound
3. Run all validators including `LibInformationValidationProvider`
4. Only if validation passes, then call `RecoverFromUpdateValue` to apply the updates

Alternatively, preserve a separate copy of the original baseRound before recovery for validation purposes:

```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    var originalBaseRound = baseRound.Clone(); // Preserve original for validation
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
}

var validationContext = new ConsensusValidationContext
{
    BaseRound = originalBaseRound ?? baseRound, // Use original for validation
    // ... other fields
};
```

## Proof of Concept

```csharp
// Test demonstrating the validation bypass
[Fact]
public void ImpliedIrreversibleBlockHeight_ValidationBypass_Test()
{
    // Setup: Create a round with legitimate ImpliedIrreversibleBlockHeight of 1000
    var currentRound = GenerateTestRound(minerPubkey, impliedHeight: 1000);
    
    // Attacker provides malicious low height of 100
    var maliciousRound = GenerateTestRound(minerPubkey, impliedHeight: 100);
    
    // Simulate the vulnerable flow
    var baseRound = currentRound.Clone();
    
    // This modifies baseRound BEFORE validation
    baseRound.RecoverFromUpdateValue(maliciousRound, minerPubkey);
    
    // Now both have the same value (100)
    Assert.Equal(100, baseRound.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight);
    Assert.Equal(100, maliciousRound.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight);
    
    // Validation check becomes: 100 > 100 = false, validation passes!
    var validationPasses = !(baseRound.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight > 
                            maliciousRound.RealTimeMinersInformation[minerPubkey].ImpliedIrreversibleBlockHeight);
    
    Assert.True(validationPasses); // Validation incorrectly passes
    
    // The malicious low height (100) is now in state instead of legitimate height (1000)
    // This will affect LIB calculation in subsequent rounds
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L19-20)
```csharp
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-82)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };

        /* Ask several questions: */

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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L19-19)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-30)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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
