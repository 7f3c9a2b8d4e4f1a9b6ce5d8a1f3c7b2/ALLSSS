### Title
Unvalidated Dictionary Access on Untrusted ExtraData Causes Consensus Validation DoS

### Summary
The `UpdateValueValidationProvider` directly accesses the `ProvidedRound.RealTimeMinersInformation` dictionary without verifying the sender's public key exists in it. Since `ProvidedRound` comes from untrusted block header `ExtraData`, a malicious miner can craft `ExtraData` with a `Round` object missing their own public key entry, causing a `KeyNotFoundException` during validation and blocking consensus.

### Finding Description

The vulnerability exists in the consensus validation flow where untrusted `ExtraData` from block headers is processed without complete validation.

**Trust Boundary Issue:**
The `ConsensusValidationContext` class exposes `ExtraData` and derived properties like `ProvidedRound` [1](#0-0) , which originates from attacker-controlled block headers.

**Initial Validation:**
When a block is received, `AEDPoSExtraDataExtractor` only validates that `SenderPubkey` matches `SignerPubkey` [2](#0-1) , but does not validate the structure or completeness of the `Round` object within `ExtraData`.

**Validation Provider Order:**
In `ValidateBeforeExecution`, validation providers are instantiated in this order [3](#0-2) :
1. `MiningPermissionValidationProvider` - validates sender is in `BaseRound` (from StateDb)
2. `TimeSlotValidationProvider`
3. `ContinuousBlocksValidationProvider`
4. Behavior-specific providers including `UpdateValueValidationProvider`

**Root Cause - Issue 1:**
The `MiningPermissionValidationProvider` only checks if `SenderPubkey` exists in `BaseRound.RealTimeMinersInformation` [4](#0-3) , which is the trusted state from StateDb. It does NOT validate that `SenderPubkey` exists in `ProvidedRound.RealTimeMinersInformation`, which comes from untrusted `ExtraData`.

**Root Cause - Issue 2:**
The `UpdateValueValidationProvider.NewConsensusInformationFilled` method directly accesses the dictionary without a `ContainsKey` check [5](#0-4) . This will throw `KeyNotFoundException` if the sender's public key is not present in `ProvidedRound.RealTimeMinersInformation`.

**Root Cause - Issue 3:**
The `UpdateValueValidationProvider.ValidatePreviousInValue` method checks if `publicKey` exists in `PreviousRound` (line 40), but then directly accesses `extraData.Round.RealTimeMinersInformation[publicKey]` without checking if the key exists in that dictionary [6](#0-5) . This is a logic error - the check is performed on the wrong dictionary.

**Contrast with Correct Pattern:**
Other validation providers like `LibInformationValidationProvider` demonstrate the correct pattern by using `ContainsKey` before accessing `ProvidedRound.RealTimeMinersInformation` [7](#0-6) .

**No Exception Handling:**
The validation pipeline does not have try-catch blocks to handle exceptions from validation providers [8](#0-7) . A `KeyNotFoundException` would propagate up and cause validation failure with an exception rather than a graceful validation result.

### Impact Explanation

**Operational Impact - Consensus Validation DoS:**
Any valid miner can craft a malicious block with `ExtraData` containing a `Round` object that omits their own public key from `RealTimeMinersInformation`. When other nodes attempt to validate this block using `ValidateConsensusBeforeExecution` [9](#0-8) , the `UpdateValueValidationProvider` will throw a `KeyNotFoundException`, causing validation to fail with an exception.

**Affected Parties:**
- All nodes attempting to validate the malicious block
- Network consensus progression is disrupted
- Block validation pipeline is blocked

**Severity Justification:**
While this does not directly steal funds or compromise state integrity, it creates a critical DoS vector in the consensus layer. The fact that any elected miner can trigger this vulnerability makes it a HIGH severity issue. The attack is deterministic, requires minimal sophistication, and can be repeated.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be an elected miner (member of current miner list)
- Being an elected miner is not a high barrier - any participant can be elected through the voting mechanism
- Attacker controls block content including `ExtraData`

**Attack Complexity:**
- LOW: Attacker simply crafts `ExtraData` with malformed `Round` object
- The `ExtraData` passes signature validation because `SenderPubkey == SignerPubkey` check succeeds
- No complex state manipulation or timing requirements

**Feasibility Conditions:**
- Attacker is in the current round's miner list (validated by `MiningPermissionValidationProvider`)
- Attacker produces a block with `Behaviour = UpdateValue`
- The crafted `ProvidedRound.RealTimeMinersInformation` dictionary excludes their own public key

**Detection Constraints:**
- Attack is immediately visible - validation fails with exception
- However, attacker can repeatedly produce such blocks during their time slots
- Network experiences persistent validation failures during attacker's mining windows

**Probability Assessment:**
HIGH - The vulnerability is trivially exploitable by any miner, requires no special conditions beyond being elected, and has been confirmed through code analysis to lack the necessary validation checks.

### Recommendation

**Fix 1 - Add ContainsKey Check in NewConsensusInformationFilled:**
Modify `UpdateValueValidationProvider.NewConsensusInformationFilled` to check if the sender's public key exists before accessing the dictionary:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    if (!validationContext.ProvidedRound.RealTimeMinersInformation.ContainsKey(validationContext.SenderPubkey))
        return false;
        
    var minerInRound =
        validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    return minerInRound.OutValue != null && minerInRound.Signature != null &&
           minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
}
```

**Fix 2 - Add ContainsKey Check in ValidatePreviousInValue:**
Modify `UpdateValueValidationProvider.ValidatePreviousInValue` to check if the public key exists in `extraData.Round` before accessing:

```csharp
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;
    
    if (!extraData.Round.RealTimeMinersInformation.ContainsKey(publicKey)) return false;

    if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

    var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
    var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    if (previousInValue == Hash.Empty) return true;

    return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
}
```

**Invariant to Enforce:**
Any access to `ProvidedRound.RealTimeMinersInformation[key]` must be preceded by a `ContainsKey(key)` check, since `ProvidedRound` originates from untrusted `ExtraData`.

**Test Case:**
Add a test that attempts to validate a block where the miner's public key is missing from `ExtraData.Round.RealTimeMinersInformation`, and verify that validation returns `Success = false` with an appropriate error message rather than throwing an exception.

### Proof of Concept

**Initial State:**
- Node is running and synchronized with the blockchain
- Attacker is an elected miner in the current round's miner list
- It is the attacker's time slot to produce a block

**Attack Steps:**

1. Attacker crafts `AElfConsensusHeaderInformation` with:
   - `SenderPubkey` = attacker's public key
   - `Behaviour` = `AElfConsensusBehaviour.UpdateValue`
   - `Round.RealTimeMinersInformation` = dictionary that does NOT contain attacker's public key as a key
   - Sign the block header with attacker's private key

2. Attacker broadcasts the block to the network

3. Other nodes receive the block and begin validation:
   - `AEDPoSExtraDataExtractor.ExtractConsensusExtraData` succeeds (SenderPubkey == SignerPubkey) ✓
   - `ValidateConsensusBeforeExecution` is called
   - `MiningPermissionValidationProvider` validates attacker is in `BaseRound` ✓
   - `TimeSlotValidationProvider` validates time slot ✓
   - `ContinuousBlocksValidationProvider` validates continuous blocks ✓
   - `UpdateValueValidationProvider.ValidateHeaderInformation` is called
   - `NewConsensusInformationFilled` attempts to access `ProvidedRound.RealTimeMinersInformation[attackerPubkey]`
   - `KeyNotFoundException` is thrown ✗

**Expected Result:**
Validation should return `ValidationResult { Success = false, Message = "Sender not in provided round information" }`

**Actual Result:**
`KeyNotFoundException` is thrown, causing validation to fail with an unhandled exception, blocking the validation pipeline

**Success Condition:**
The attack is successful if other nodes fail to validate the block due to an exception rather than a graceful validation failure. This can be confirmed by observing exception logs on validating nodes.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L32-32)
```csharp
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-16)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
```csharp
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
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-17)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L29-30)
```csharp
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L40-45)
```csharp
        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-24)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-80)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
```
