# Audit Report

## Title
LIB Height Reset During Term Transition Due to Missing Validation

## Summary
The AEDPoS consensus contract lacks LIB (Last Irreversible Block) height validation during NextTerm transitions, allowing a malicious miner to reset the contract's `ConfirmedIrreversibleBlockHeight` to an arbitrary lower value. This corrupts the contract state and violates the critical invariant that LIB heights must monotonically increase.

## Finding Description

The vulnerability exists because the NextTerm behavior validation does not include the `LibInformationValidationProvider` that prevents LIB heights from decreasing. 

During NextTerm validation, only `RoundTerminateValidationProvider` is added to the validation providers: [1](#0-0) 

In contrast, UpdateValue behavior correctly includes the `LibInformationValidationProvider`: [2](#0-1) 

The `LibInformationValidationProvider` checks whether LIB heights decrease and rejects such attempts: [3](#0-2) 

The `NextTermInput.ToRound()` method preserves attacker-controlled LIB heights without validation: [4](#0-3) 

These values are then stored directly in contract state: [5](#0-4) [6](#0-5) 

Additionally, the round hash validation in `ValidateConsensusAfterExecution` cannot detect LIB manipulation because `GetCheckableRound` explicitly excludes the LIB fields from the hash computation: [7](#0-6) 

## Impact Explanation

**Contract State Corruption:**
The contract's `ConfirmedIrreversibleBlockHeight` state can be reset to any lower value chosen by the attacker, violating the critical invariant that LIB heights must monotonically increase. This creates state inconsistency between the consensus contract and the blockchain node.

**Operational Impact:**
The `GetMaximumBlocksCount()` method relies on the stored LIB values to assess blockchain health: [8](#0-7) 

Manipulated LIB values can cause the blockchain to be incorrectly assessed as being in "Abnormal" or "Severe" status, potentially reducing the maximum blocks count to 1 and triggering false `IrreversibleBlockHeightUnacceptable` events.

**View Method Inconsistency:**
Any external contracts or clients querying round information will receive incorrect LIB heights. The corrupted values propagate to subsequent rounds when new rounds are generated: [9](#0-8) [10](#0-9) 

**Mitigation Factor:**
Node-level protection prevents the actual chain LIB from decreasing: [11](#0-10) 

However, this does not excuse the contract-level vulnerability, as contract state corruption itself violates protocol invariants and affects contract operations.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner (passes PreCheck authorization)
- Must be scheduled to produce the NextTerm block
- Given sufficient miners and term duration, this opportunity occurs regularly at each term transition

**Attack Complexity:**
Low complexity - the attacker simply crafts consensus extra data with modified LIB height values before mining the NextTerm block. No sophisticated techniques are required, and the modified data passes all validations due to the missing validator.

**Detection Difficulty:**
The manipulated block passes all consensus validations. Contract state corruption is only visible through direct state queries, with no immediate observable impact due to node-level protections.

## Recommendation

Add `LibInformationValidationProvider` to the NextTerm validation providers list:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
```

This ensures that LIB heights are validated during NextTerm transitions, preventing contract state corruption.

## Proof of Concept

```csharp
[Fact]
public async Task NextTerm_Should_Reject_Decreased_LIB_Height()
{
    // Setup: Create initial round with LIB height = 100
    var initialRound = GenerateRoundWithLIBHeight(100);
    await InitializeConsensusWithRound(initialRound);
    
    // Attack: Miner crafts NextTermInput with LIB height = 50 (lower than current)
    var maliciousNextTermInput = new NextTermInput
    {
        RoundNumber = initialRound.RoundNumber + 1,
        TermNumber = initialRound.TermNumber + 1,
        ConfirmedIrreversibleBlockHeight = 50, // Malicious: Lower than current 100
        ConfirmedIrreversibleBlockRoundNumber = initialRound.ConfirmedIrreversibleBlockRoundNumber,
        RandomNumber = GenerateRandomNumber(),
        // ... other required fields
    };
    
    // Execute: Malicious miner calls NextTerm
    var result = await ConsensusContract.NextTerm.SendAsync(maliciousNextTermInput);
    
    // Verify: Without the fix, this succeeds and corrupts state
    // With the fix, this should be rejected
    var currentRound = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Vulnerability: Current LIB height is now 50 instead of staying >= 100
    Assert.True(currentRound.ConfirmedIrreversibleBlockHeight == 50); // Proves vulnerability
}
```

## Notes

This vulnerability represents a critical contract-level state integrity issue. While node-level protections prevent the actual blockchain LIB from decreasing, the consensus contract's state becomes corrupted and inconsistent with the node state. This affects all operations that rely on the contract's LIB values, including blockchain health monitoring and cross-contract queries about irreversibility. The fix is straightforward: include `LibInformationValidationProvider` in NextTerm validation, consistent with how UpdateValue behavior is already protected.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L196-196)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L199-206)
```csharp
        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L25-26)
```csharp
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L51-52)
```csharp
        round.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        round.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/IrreversibleBlockFoundLogEventProcessor.cs (L60-61)
```csharp
            if (chain.LastIrreversibleBlockHeight > irreversibleBlockFound.IrreversibleBlockHeight)
                return;
```
