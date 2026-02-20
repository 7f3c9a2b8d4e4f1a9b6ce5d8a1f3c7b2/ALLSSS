# Audit Report

## Title
Signature Non-Repudiation Vulnerability: Unvalidated Signature Mismatch Between Block Header and Transaction State

## Summary
The AEDPoS consensus system fails to validate that the signature in the block header matches the signature stored in the transaction state during `UpdateValue` operations. A malicious miner can provide a valid signature for block validation but store a different signature (including `Hash.Empty`) in the consensus state, breaking signature non-repudiation and corrupting the signature chain used for randomness generation and mining order calculations.

## Finding Description

The vulnerability exists in the dual-path signature handling during `UpdateValue` consensus operations:

**Path 1: Block Header Signature**

The block header receives a simplified Round object via `GetUpdateValueRound()` which copies the signature from the current round state. [1](#0-0)  This is called during header generation when `isGeneratingTransactions` is false. [2](#0-1) 

**Path 2: Transaction Signature**

The transaction receives an `UpdateValueInput` via `ExtractInformationToUpdateConsensus()` which also copies the signature from the current round state. [3](#0-2)  During transaction execution, this signature is stored directly to state. [4](#0-3) 

**Missing Cross-Validation**

The `UpdateValueValidationProvider` only verifies that the header signature exists and is non-empty, but does not compare it with the transaction signature. [5](#0-4) 

**Ineffective Post-Execution Validation**

The `ValidateConsensusAfterExecution()` attempts validation through hash comparison, but `RecoverFromUpdateValue()` modifies the current round in-place by overwriting the state signature with the header signature before comparison occurs. [6](#0-5)  The method then assigns this modified round back to `headerInformation.Round`, making the subsequent hash comparison meaningless as both sides reference the same object. [7](#0-6) 

**Attack Vector**

A malicious miner controlling their node software can modify the consensus contract or node implementation to provide different signatures when `GetConsensusBlockExtraData` is called for header generation versus transaction generation. Since both methods load fresh Round objects from state and these calls occur at different times, the miner can inject different signature values by modifying their node to intercept these calls or patch the extraction methods.

## Impact Explanation

**Consensus Integrity Corruption:**

The signature is critical for consensus operations. The `CalculateSignature()` method aggregates all miner signatures through XOR operations to compute future signatures. [8](#0-7)  A corrupted signature in state breaks this cryptographic chain, affecting all subsequent rounds.

Mining order for the next round is calculated directly from the signature value through modulo operations. [9](#0-8)  A manipulated signature affects the fairness and deterministic nature of miner selection. [10](#0-9) 

**Specific Harms:**
1. **Non-Repudiation Failure**: A miner can provide a valid signature for validation but store `Hash.Empty` in state, denying participation while appearing compliant
2. **Randomness Corruption**: Future random number generation depends on signature chain integrity through `GetLatestSignature` [11](#0-10) 
3. **Fairness Violation**: Mining order calculations use corrupted signatures, affecting deterministic miner selection
4. **Consensus Instability**: Signature chain breaks propagate through subsequent rounds via `CalculateSignature()` calls [12](#0-11) 

**Severity: MEDIUM** - Requires a malicious miner (privileged but not trusted role per threat model) but breaks critical consensus invariants with network-wide impact.

## Likelihood Explanation

**Attacker Capabilities:**
- Must be an authorized miner (privileged but distributed role, explicitly NOT in the trusted role list which only includes: genesis method-fee provider, organization controllers, and consensus system contracts)
- Must modify node implementation to generate mismatched signatures between header and transaction
- Node modification is technically feasible for sophisticated actors with access to their own mining infrastructure

**Attack Complexity:**
- LOW - Once node is modified, exploitation is straightforward
- The miner controls when and how `GetConsensusBlockExtraData` is called with different parameters [13](#0-12) 
- Attacker can modify `ExtractInformationToUpdateConsensus` or the trigger information provider to use different signatures

**Feasibility Conditions:**
- Attacker controls a miner node and its software
- No contract-level validation prevents the attack - validation only examines the header [14](#0-13) 
- Block validation passes with the header signature
- State stores the transaction signature without cross-checking

**Detection Difficulty:**
- Difficult to detect without explicit comparison of historical block header data versus stored consensus state signatures
- Attack may only become apparent when signature chain is used for mining order calculation or randomness generation in future rounds

**Probability: MEDIUM-HIGH** - Technical barrier exists (node modification and maintaining miner status) but no protocol-level prevention mechanism exists once these barriers are overcome.

## Recommendation

Add cross-validation between header and transaction signatures in `ValidateConsensusAfterExecution()`:

```csharp
public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
{
    var headerInformation = new AElfConsensusHeaderInformation();
    headerInformation.MergeFrom(input.Value);
    if (TryToGetCurrentRoundInformation(out var currentRound))
    {
        if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
        {
            // VALIDATE SIGNATURE MATCH BEFORE RECOVERY
            var pubkey = headerInformation.SenderPubkey.ToHex();
            var headerSignature = headerInformation.Round.RealTimeMinersInformation[pubkey].Signature;
            var stateSignature = currentRound.RealTimeMinersInformation[pubkey].Signature;
            
            if (headerSignature != stateSignature)
            {
                return new ValidationResult
                {
                    Success = false,
                    Message = "Header signature does not match transaction state signature"
                };
            }
            
            headerInformation.Round =
                currentRound.RecoverFromUpdateValue(headerInformation.Round,
                    headerInformation.SenderPubkey.ToHex());
        }
        // ... rest of validation logic
    }
    return new ValidationResult { Success = true };
}
```

Alternatively, validate at the transaction execution level by comparing the transaction input signature with the header signature extracted from consensus extra data.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a test miner node with modified consensus contract
2. Modifying `ExtractInformationToUpdateConsensus()` to return `Hash.Empty` as signature
3. Keeping `GetUpdateValueRound()` unchanged to provide valid header signature
4. Executing `UpdateValue` transaction
5. Observing that validation passes despite signature mismatch
6. Verifying stored state contains `Hash.Empty` while block header contains valid signature
7. Confirming signature chain corruption in subsequent `CalculateSignature()` calls

The core issue is that `RecoverFromUpdateValue()` masks the discrepancy by overwriting state with header data before comparison, and no earlier validation checks for signature consistency between the two paths.

## Notes

This vulnerability represents a fundamental gap in the consensus validation logic where two parallel paths (header and transaction) carry the same critical field (signature) but are never cross-validated. The validation architecture assumes these paths are always consistent, but this assumption can be violated by a node operator who controls their own mining software. While this requires privileged access (miner status), miners are explicitly outside the trusted roles boundary and should not be able to corrupt consensus state in this manner.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L11-24)
```csharp
    public Round GetUpdateValueRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = pubkey,
                    OutValue = minerInRound.OutValue,
                    Signature = minerInRound.Signature,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L13-31)
```csharp
    private BytesValue GetConsensusBlockExtraData(BytesValue input, bool isGeneratingTransactions = false)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);

        Assert(triggerInformation.Pubkey.Any(), "Invalid pubkey.");

        TryToGetCurrentRoundInformation(out var currentRound);

        var publicKeyBytes = triggerInformation.Pubkey;
        var pubkey = publicKeyBytes.ToHex();

        var information = new AElfConsensusHeaderInformation();
        switch (triggerInformation.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L35-38)
```csharp
        return new UpdateValueInput
        {
            OutValue = minerInRound.OutValue,
            Signature = minerInRound.Signature,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L95-106)
```csharp
    private Hash GetLatestSignature(Round currentRound)
    {
        var latestSignature = currentRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .LastOrDefault(m => m.Signature != null)?.Signature;
        if (latestSignature != null) return latestSignature;
        if (TryToGetPreviousRoundInformation(out var previousRound))
            latestSignature = previousRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order)
                .LastOrDefault(m => m.Signature != null)
                ?.Signature;

        return latestSignature;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-244)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-17)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L25-36)
```csharp
        // Set next round miners' information of miners who successfully mined during this round.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-80)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
```
