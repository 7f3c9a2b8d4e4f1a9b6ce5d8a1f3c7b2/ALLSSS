# Audit Report

## Title
Signature Forgery Enables Mining Order Manipulation in AEDPoS Consensus

## Summary
The AEDPoS consensus mechanism fails to validate that miner-provided signature values match the expected cryptographic calculation, allowing malicious miners to forge arbitrary signatures and manipulate their mining position in subsequent rounds. This breaks the fundamental randomness guarantee of the consensus mechanism.

## Finding Description

The AEDPoS consensus relies on a signature-based randomness mechanism where each miner's next-round mining order is deterministically calculated from a signature value. During honest operation, this signature is computed by XORing the miner's `previousInValue` with all previous round signatures via `CalculateSignature()`. [1](#0-0) 

When a miner produces a block with UpdateValue behavior, the honest flow calculates the signature correctly. [2](#0-1) 

The vulnerability exists because the validation pipeline never verifies this calculation is correct. The `UpdateValueValidationProvider` only performs superficial checks - it verifies signature and outValue are non-empty, and validates that `Hash(previousInValue) == previousOutValue`, but crucially never validates that the signature matches what `CalculateSignature()` would produce. [3](#0-2) 

During validation, `RecoverFromUpdateValue()` directly copies the signature from provided data without any cryptographic verification. [4](#0-3)  It also copies `SupposedOrderOfNextRound` values for all miners. [5](#0-4) 

Subsequently, `ProcessUpdateValue()` directly assigns both the signature and `SupposedOrderOfNextRound` from user input to the miner's round information in state. [6](#0-5) 

The vulnerability is exploitable because `SupposedOrderOfNextRound` is calculated directly from the signature value using modulo arithmetic - the miner's order is `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [7](#0-6) 

When transitioning to the next round, miners who successfully mined are assigned their actual mining order based on their `FinalOrderOfNextRound` value, which is derived from the signature-based calculation. [8](#0-7) 

**Attack Execution:**
1. Malicious miner calculates desired order position (e.g., order = 1 for mining first)
2. Works backwards to find a signature Hash value where `signature.ToInt64() % minersCount == (desiredOrder - 1)`
3. Constructs `UpdateValueInput` with the forged signature and corresponding `SupposedOrderOfNextRound`
4. Submits the block with this consensus data during their legitimate mining time slot
5. Validation passes because no signature correctness check exists
6. The forged order value propagates to the next round as their actual mining position

## Impact Explanation

**Critical Consensus Integrity Breach:**

This vulnerability breaks the core security property that mining order must be unpredictably randomized. A malicious miner can consistently choose to mine first in each round, providing them with:

- Maximum MEV (Miner Extractable Value) opportunities to extract value from transaction ordering
- Ability to reorder or censor transactions within their block production window  
- Greater influence over which transactions get included in blocks
- First-mover advantage in capturing profitable transactions
- Potential for unfair reward accumulation across multiple rounds

The randomness guarantee is fundamental to consensus fairness - without it, the protocol cannot ensure equal opportunity among miners. This affects all network participants by allowing systematic value extraction by malicious miners at the expense of fair competition.

**Severity: CRITICAL** - Directly compromises a foundational security property of the blockchain consensus mechanism, enabling ongoing exploitation without detection.

## Likelihood Explanation

**High Likelihood:**

The attacker must be an authorized miner, which is a realistic precondition since the attack is performed BY a miner during their legitimate mining window. The miner authorization is verified by existing permission checks. [9](#0-8) 

**Attack Complexity: LOW**
- Simple arithmetic calculation to determine the signature value needed for desired order
- No complex preconditions or state manipulation required  
- Executed through normal block production operations
- No additional transactions or approvals needed

**Detection: IMPOSSIBLE**
- All existing validation checks pass with forged values
- The post-execution validation in `ValidateConsensusAfterExecution` succeeds because `RecoverFromUpdateValue()` modifies the current round to match provided data before comparison. [10](#0-9) 
- No on-chain mechanism can detect the forgery without re-computing the expected signature using `CalculateSignature()`
- Repeatable every round without risk of detection

## Recommendation

Add signature verification in the `UpdateValueValidationProvider` to ensure the provided signature matches the expected calculation:

```csharp
private bool ValidateSignatureCorrectness(ConsensusValidationContext validationContext)
{
    var providedSignature = validationContext.ExtraData.Round.RealTimeMinersInformation[validationContext.SenderPubkey].Signature;
    var previousInValue = validationContext.ExtraData.Round.RealTimeMinersInformation[validationContext.SenderPubkey].PreviousInValue;
    
    if (previousInValue == null || previousInValue == Hash.Empty)
        return true; // First round case
    
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
    return providedSignature == expectedSignature;
}
```

Add this check to the `ValidateHeaderInformation` method before returning success, ensuring signature integrity is cryptographically verified.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set up a multi-miner consensus round
2. Have a malicious miner forge a signature value where `ToInt64() % minersCount == 0`
3. Submit UpdateValue with the forged signature
4. Verify validation passes
5. Transition to next round
6. Confirm the malicious miner consistently gets order = 1

The vulnerability is confirmed by the absence of any signature correctness validation in the codebase - no comparison exists between provided signatures and `CalculateSignature()` output anywhere in the validation pipeline.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-49)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L14-20)
```csharp
        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-101)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
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
