# Audit Report

## Title
Mining Order Manipulation via Unvalidated SupposedOrderOfNextRound and TuneOrderInformation

## Summary
The AEDPoS consensus contract accepts `SupposedOrderOfNextRound` and `TuneOrderInformation` values from miner-provided input without cryptographically validating that they match the deterministic calculation from the miner's signature. This allows a malicious miner to manipulate mining order in subsequent rounds, consistently positioning themselves first to maximize block rewards while disadvantaging honest miners.

## Finding Description

The vulnerability exists because mining order values are calculated during consensus extra data generation but never re-validated during block validation or execution.

**Root Cause - Order Calculation Only Occurs During Generation:**

The correct calculation of `SupposedOrderOfNextRound` from a miner's signature is: [1](#0-0) 

This calculation occurs only when generating consensus extra data via `ApplyNormalConsensusData`: [2](#0-1) 

**Vulnerability 1 - ProcessUpdateValue Blindly Accepts Input Values:**

During block execution, `ProcessUpdateValue` directly uses the provided values without recalculation: [3](#0-2) 

The `TuneOrderInformation` is blindly applied to modify other miners' orders: [4](#0-3) 

**Vulnerability 2 - UpdateValueValidationProvider Insufficient:**

The validation provider only checks that `OutValue` and `Signature` are filled, but does NOT validate that `SupposedOrderOfNextRound` matches the calculation from the signature: [5](#0-4) 

**Vulnerability 3 - RecoverFromUpdateValue Blindly Copies:**

During pre-execution validation, the recovery process copies order values from provided data without recalculation: [6](#0-5) 

**Vulnerability 4 - After-Execution Validation Ineffective:**

The after-execution validation compares rounds that both contain the same manipulated values: [7](#0-6) 

Since `RecoverFromUpdateValue` copies the manipulated values into both rounds being compared, the hash comparison cannot detect tampering.

**Attack Path:**

A malicious miner extracts `TuneOrderInformation` during consensus extra data generation: [8](#0-7) 

The miner can modify these values before including them in the block header. The only node-level validation checks that the sender pubkey matches the block signer, but does not recalculate orders: [9](#0-8) 

## Impact Explanation

**Critical Consensus Integrity Violation:**

The manipulated `FinalOrderOfNextRound` values directly determine the mining schedule for the next round. When generating the next round, miners are scheduled according to their `FinalOrderOfNextRound`: [10](#0-9) 

**Concrete Harm:**

1. **Unfair Mining Advantage**: Attacker can set their `FinalOrderOfNextRound = 1` to consistently mine first in subsequent rounds, maximizing their block production opportunities
2. **Reward Misallocation**: First miners have higher probability of producing blocks and earning rewards; the attacker gains disproportionate rewards at the expense of honest miners
3. **Consensus Fairness Breakdown**: The security guarantee that mining order is unpredictably determined from signature hashes is completely bypassed
4. **Competitor Suppression**: Attacker can use malicious `TuneOrderInformation` to push specific honest miners to later positions, reducing their mining opportunities

**Severity**: CRITICAL - This breaks a core consensus invariant (miner schedule integrity) and directly impacts economic fairness and block production distribution across all network participants.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an authorized miner in the current round (standard precondition for block production)
- Control over their own node software (typical for all miners)
- No special cryptographic capabilities beyond normal block signing

**Attack Feasibility**: HIGH

The attack is straightforward:
1. Node calls `GetConsensusExtraData` through standard miner process
2. Miner parses the returned `AElfConsensusHeaderInformation` protobuf
3. Miner modifies `SupposedOrderOfNextRound` to desired value (e.g., 1 to mine first)
4. Miner modifies `TuneOrderInformation` to suppress competitors
5. Miner serializes modified data and includes in block header
6. Miner signs block with their own key

**Why Block Validation Passes:**
- `UpdateValueValidationProvider` doesn't check order calculations
- `RecoverFromUpdateValue` blindly copies manipulated values
- After-execution hash comparison compares manipulated values with themselves
- No code path recalculates expected values from signatures

**Detection**: NONE - The contract has no mechanism to detect order manipulation since it never recalculates the expected values from signatures.

**Economic Rationality**: Highly profitable - mining rewards justify the manipulation, especially for validators with significant stake who can exploit this persistently across many rounds.

## Recommendation

Add validation in `UpdateValueValidationProvider` to recalculate and verify `SupposedOrderOfNextRound` matches the signature-derived value:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation()
private bool ValidateSupposedOrderCalculation(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var signature = minerInRound.Signature;
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    
    var expectedOrder = GetAbsModulus(signature.ToInt64(), minersCount) + 1;
    
    if (minerInRound.SupposedOrderOfNextRound != expectedOrder)
    {
        return false;
    }
    
    return true;
}
```

Additionally, validate that `TuneOrderInformation` only contains miners whose orders were previously conflicted (have different `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` in the previous state), and that the new orders don't create new conflicts.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up an AEDPoS test environment with multiple miners
2. Having a miner generate proper consensus extra data via `GetConsensusExtraData`
3. Modifying the `SupposedOrderOfNextRound` to 1 (to mine first)
4. Including the modified data in a block
5. Observing that validation passes and the miner is scheduled first in the next round
6. Verifying no error or revert occurs

The test would show that a miner can arbitrarily set their mining order without triggering any validation failure, confirming the absence of signature-based order verification.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L31-32)
```csharp
        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
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
```
