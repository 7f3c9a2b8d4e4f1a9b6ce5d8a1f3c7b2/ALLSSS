# Audit Report

## Title
Missing Signature Correctness Validation in UpdateValue Allows Mining Order Manipulation

## Summary
The AEDPoS consensus contract accepts arbitrary signature values in `UpdateValue` operations without validating they match the protocol-specified calculation. Since signatures directly determine mining order in subsequent rounds through modulo arithmetic, malicious miners can manipulate their block production schedule to gain unfair advantages in rewards and transaction ordering influence.

## Finding Description

The vulnerability exists in the signature validation flow for consensus `UpdateValue` operations. When miners produce blocks, they submit an `UpdateValueInput` containing a signature field that should be deterministically calculated from their previous round's in-value and all miners' signatures from the previous round.

**Signature Generation (Honest Path):**

The correct signature calculation occurs during block production using `previousRound.CalculateSignature(previousInValue)`: [1](#0-0) 

The `CalculateSignature` method XORs the previous in-value with all miner signatures: [2](#0-1) 

This signature is then extracted into the transaction: [3](#0-2) 

**Missing Validation:**

When the `UpdateValue` transaction is processed, the provided signature is blindly accepted without verification: [4](#0-3) 

The validation provider only checks that the signature field is non-empty, not that it's correctly calculated: [5](#0-4) 

The previous in-value is validated (that it hashes to the previous out-value), but the signature itself is never compared against the expected value: [6](#0-5) 

**Impact on Mining Order:**

The signature directly determines each miner's position in the next round through modulo arithmetic: [7](#0-6) 

**Attack Execution:**

Since miners control both the block header consensus extra data and the UpdateValue transaction parameter, they can:
1. Calculate which signature value (as int64) modulo miner count gives their desired position
2. Set both the header's `Round.Signature` and transaction's `UpdateValueInput.Signature` to that value
3. Submit the block with modified signature
4. Pass all validations since none check signature correctness
5. Gain their chosen position in the next round's mining schedule

The `ValidateConsensusAfterExecution` only ensures consistency between header and final state, but neither validates the signature is correctly calculated: [8](#0-7) 

## Impact Explanation

This vulnerability breaks the **fairness and unpredictability** guarantees of the AEDPoS consensus mechanism. The signature is designed to be deterministic based on all miners' inputs, creating a fair distribution of mining opportunities. By allowing arbitrary signatures, the protocol permits:

1. **Disproportionate Block Rewards** - Miners can position themselves to mine more frequently, gaining larger shares of block production rewards
2. **Transaction Ordering Influence** - More frequent block production grants greater control over transaction inclusion and ordering
3. **Potential Collusion** - Multiple malicious miners could coordinate signature manipulation to dominate the mining schedule

While this doesn't enable direct fund theft, it fundamentally undermines consensus integrity - a critical protocol invariant. The impact is categorized as **Medium to High** because it allows systematic gaming of the consensus mechanism by any authorized miner.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:

**Attacker Capabilities:** Any authorized miner in the current round can execute this attack with no additional privileges required beyond normal mining rights.

**Attack Complexity:** Low - The miner simply needs to:
- Determine their desired mining position (1 to N)
- Calculate: `targetModuloResult = desiredPosition - 1`
- Find any signature value where: `GetAbsModulus(signature.ToInt64(), minersCount) == targetModuloResult`
- Submit UpdateValue with this crafted signature

**Feasibility Conditions:**
- Attacker must be an authorized miner (standard consensus threat model assumption)
- No special preconditions or state requirements
- Can be executed on every block produced

**Detection Constraints:** The attack is completely silent - no validation failures or events indicate signature manipulation. The VRF verification validates the `random_number` field (used for random hash generation), which is separate from the `Signature` field used for order calculation: [9](#0-8) 

The signature correctness is never verified anywhere in the codebase.

## Recommendation

Add signature validation in the `UpdateValueValidationProvider` or `ProcessUpdateValue` method to verify that the provided signature matches the expected calculation:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation or ProcessUpdateValue:
if (validationContext.PreviousRound != null && 
    validationContext.PreviousRound.RoundNumber != 0)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var providedSignature = minerInRound.Signature;
    var previousInValue = minerInRound.PreviousInValue;
    
    if (previousInValue != null && previousInValue != Hash.Empty)
    {
        var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
        if (providedSignature != expectedSignature)
        {
            return new ValidationResult { Message = "Incorrect signature value." };
        }
    }
}
```

This ensures that miners cannot manipulate their signatures to gain favorable mining positions.

## Proof of Concept

A proof of concept would demonstrate:
1. Creating a test scenario with multiple miners in a round
2. Calculating the signature value needed to achieve a desired mining position
3. Submitting an UpdateValue transaction with the crafted signature
4. Verifying the miner receives their chosen position in the next round
5. Confirming no validation errors occur

The test would show that by choosing signature `S` such that `GetAbsModulus(S.ToInt64(), minersCount) + 1 = desiredPosition`, a miner can deterministically control their next round position, breaking the fairness guarantee of the consensus protocol.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L38-38)
```csharp
            Signature = minerInRound.Signature,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L76-78)
```csharp
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-244)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-48)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
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
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```
