# Audit Report

## Title
Malicious Miner Can Manipulate Next Round Mining Order Through Unvalidated SupposedOrderOfNextRound

## Summary
A malicious miner can arbitrarily set their `SupposedOrderOfNextRound` value when calling `UpdateValue`, allowing them to manipulate their mining position in the next round. The contract fails to validate that this value is correctly calculated from the miner's signature hash, breaking the deterministic consensus ordering mechanism.

## Finding Description

The AEDPoS consensus protocol is designed to deterministically calculate each miner's position in the next round using the formula `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [1](#0-0) 

However, the contract contains a critical validation gap in the `UpdateValue` transaction flow:

**1. Missing Validation in UpdateValueValidationProvider:**
The validation provider only checks that `OutValue` and `Signature` are filled, and validates `PreviousInValue` correctness. It does NOT validate `SupposedOrderOfNextRound`. [2](#0-1) 

**2. Direct Acceptance in ProcessUpdateValue:**
The contract directly accepts the miner-provided `SupposedOrderOfNextRound` value without any validation against the signature calculation. [3](#0-2) 

**3. Unvalidated Copy in RecoverFromUpdateValue:**
During validation, the recovery process copies the provided values without recalculating or validating them. [4](#0-3) 

**4. Next Round Uses Manipulated Order:**
When generating the next round, miners are ordered by `FinalOrderOfNextRound`, which is initially set from the unvalidated `SupposedOrderOfNextRound`. [5](#0-4) 

**Why Hash Validation Doesn't Protect:**
The hash validation in `ValidateConsensusAfterExecution` compares the header round hash with the current round hash, but only after `RecoverFromUpdateValue` has already copied the manipulated values from the header. Since the malicious miner controls both the block header extra data and the transaction parameters, they can ensure both contain the same (manipulated) values, making the hashes match. [6](#0-5) 

The hash calculation includes `SupposedOrderOfNextRound` in the checkable round data. [7](#0-6) 

## Impact Explanation

This vulnerability breaks a fundamental consensus invariant: deterministic mining order calculation. The impacts include:

1. **Consensus Ordering Manipulation:** Malicious miners can consistently choose favorable mining positions (e.g., always mining first in the round by setting order to 1), gaining first-mover advantages for transaction ordering and MEV extraction.

2. **Unfair Mining Advantages:** Attackers can avoid unfavorable time slots and strategically position themselves relative to other miners, undermining consensus fairness.

3. **Coordination Attack Potential:** Multiple colluding miners could coordinate their orders to dominate block production schedules, potentially affecting consensus liveness.

This is a **critical severity** issue as it directly violates consensus integrity guarantees.

## Likelihood Explanation

**Attack Complexity: Low**
- A miner only needs to modify their node software to override the `SupposedOrderOfNextRound` field in the `UpdateValueInput` before broadcasting
- The correct calculation logic exists in `ApplyNormalConsensusData` but is never enforced during validation

**Attacker Capabilities:**
- Must be an active consensus miner (realistic requirement in AEDPoS)
- No special privileges beyond normal miner status required

**Detection Difficulty:**
- Without explicit validation comparing the provided value against the signature calculation, the manipulation is undetectable by the contract
- Would require off-chain analysis of signature-to-order relationships to detect

**Economic Incentives:**
- Cost: Zero beyond running a mining node
- Benefit: Consistent mining position advantages, MEV opportunities
- Risk: Low detection probability

The likelihood is **high** for any sophisticated miner motivated by mining advantages.

## Recommendation

Add validation in `UpdateValueValidationProvider` to verify that the provided `SupposedOrderOfNextRound` matches the expected calculation from the signature:

```csharp
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

Call this validation in `ValidateHeaderInformation` and reject if the validation fails.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Deploy AEDPoS contract with multiple miners
2. Have a miner produce a block with a manipulated `SupposedOrderOfNextRound` value (e.g., setting it to 1 regardless of their signature)
3. Verify the transaction is accepted without rejection
4. Generate the next round and verify the miner is positioned at order 1
5. Confirm this differs from what their signature hash would have calculated

The test would prove that miners can arbitrarily choose their next round position without validation rejection.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-33)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-27)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```
