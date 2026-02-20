# Audit Report

## Title
Missing LIB Validation in NextTerm Allows Malicious Miners to DoS Blockchain via Inconsistent Irreversible Block Fields

## Summary
The AEDPoS consensus validation logic contains a critical gap where `LibInformationValidationProvider` is not applied to NextTerm behavior transitions. This allows a malicious miner to inject arbitrary `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` values, triggering blockchain-wide denial-of-service by forcing all miners into single-block production mode.

## Finding Description

The vulnerability stems from inconsistent validation across consensus behaviors. When validating consensus information before execution, the system applies different validation providers based on behavior type.

For UpdateValue behavior, `LibInformationValidationProvider` is explicitly added to validate LIB field consistency: [1](#0-0) 

However, for NextTerm behavior, only `RoundTerminateValidationProvider` is added, completely omitting LIB validation: [2](#0-1) 

The `LibInformationValidationProvider` validates that LIB values don't regress: [3](#0-2) 

Additionally, the Round hash computation used in post-execution validation excludes LIB fields. The `GetCheckableRound` method only includes RoundNumber, TermNumber, RealTimeMinersInformation, and BlockchainAge: [4](#0-3) 

This means modified LIB values won't break the hash comparison in `ValidateConsensusAfterExecution`.

**Attack Flow:**

During NextTerm generation, the Round object includes LIB fields copied from the current round: [5](#0-4) 

These fields are included in the NextTermInput structure: [6](#0-5) 

When ProcessNextTerm executes, it converts the input to a Round object, preserving the LIB fields: [7](#0-6) 

The entire Round object (including manipulated LIB fields) is stored in state: [8](#0-7) 

## Impact Explanation

The malicious LIB values directly affect blockchain operation through `GetMaximumBlocksCount`, which reads the corrupted values: [9](#0-8) 

The `BlockchainMiningStatusEvaluator` determines status based on the gap between current round and LIB round: [10](#0-9) 

When Severe status is triggered (gap ≥ 8 rounds), the blockchain enters emergency mode: [11](#0-10) 

**Attack Scenario:**
If an attacker sets `ConfirmedIrreversibleBlockRoundNumber = 10` while current round is 100:
- Calculation: `100 >= 10 + 8` → Status becomes `Severe`
- MaximumBlocksCount reduces to 1
- All miners forced into single-block production
- Blockchain throughput collapses
- Effect persists entire term duration (potentially thousands of blocks)

**Impact Severity:**
- Blockchain-wide DoS affecting all miners and users
- Persistent degradation for complete term duration
- Network becomes practically unusable
- Severe availability violation

## Likelihood Explanation

**Attacker Requirements:**
Must be a current miner in the active miner list. Access control validates miner membership: [12](#0-11) 

**Attack Complexity:**
1. Wait for NextTerm transition opportunity (when scheduled to produce NextTerm block)
2. Obtain legitimate consensus header via GetConsensusExtraData
3. Modify LIB fields in Round object before block production
4. Produce block with modified header
5. Block passes all validations (missing LibInformationValidationProvider)
6. Malicious values stored in state

**Feasibility:**
- **High**: Only requires regular miner privileges (no special elevated access)
- **Repeatable**: Can execute at every term transition
- **Undetectable**: No validation failure, appears as legitimate block
- **Rational attack**: Compromised miner could disrupt competitors/network

**Probability Assessment:** MEDIUM-HIGH
- Limited attacker pool (must be miner)
- But miners not fully trusted in security model
- Single compromised miner sufficient
- Severe impact warrants high priority

## Recommendation

Add `LibInformationValidationProvider` to NextTerm validation logic in `AEDPoSContract_Validation.cs`:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS LINE
    break;
```

This ensures LIB fields are validated for consistency during term transitions, preventing injection of malicious values.

## Proof of Concept

A malicious miner can exploit this vulnerability by:
1. Waiting for term transition
2. Generating NextTermInput with artificially low `ConfirmedIrreversibleBlockRoundNumber` (e.g., 1)
3. Producing NextTerm block with modified consensus header
4. Block passes validation and corrupted LIB stored in state
5. All subsequent blocks see Severe status, forcing single-block production mode
6. Blockchain enters degraded state for entire term duration

The test would validate that a NextTerm block with manipulated LIB fields passes validation and causes GetMaximumBlocksCount to return 1 (Severe status), demonstrating the DoS condition.

## Notes

This vulnerability exploits two related gaps:
1. Missing `LibInformationValidationProvider` in NextTerm validation pipeline
2. Exclusion of LIB fields from `GetCheckableRound` hash computation

Both mechanisms must work together to prevent this attack. The recommended fix addresses the validation gap, which is the primary defense point before state modification occurs.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L34-35)
```csharp
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L163-163)
```csharp
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L25-26)
```csharp
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-66)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L127-128)
```csharp
            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-20)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
```
