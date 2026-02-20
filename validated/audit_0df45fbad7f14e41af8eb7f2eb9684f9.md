# Audit Report

## Title
Unhandled KeyNotFoundException in RecoverFromUpdateValue During Miner Replacement Causes Block Validation DoS

## Summary
The `RecoverFromUpdateValue` method contains an unprotected dictionary access in a foreach loop that causes a `KeyNotFoundException` when a miner replacement transaction executes in the same block as UpdateValue consensus behavior. This results in block validation failure and consensus disruption.

## Finding Description

The vulnerability exists in the `RecoverFromUpdateValue` method where a foreach loop iterates over all miners in the provided round and directly accesses them in the current round's dictionary without existence checks. [1](#0-0) 

While lines 10-12 protect the specific `pubkey` parameter, the foreach loop at lines 22-30 assumes all miners from `providedRound` exist in the current round's `RealTimeMinersInformation` dictionary. [2](#0-1)  This assumption breaks when miner replacement occurs.

The attack sequence:

1. **Miner replacement execution**: When `ReplaceCandidatePubkey` is called, it triggers `RecordCandidateReplacement` in the consensus contract. [3](#0-2) [4](#0-3) 

2. **State modification**: The consensus contract removes the old pubkey and adds the new pubkey to the current round. [5](#0-4) 

3. **Post-execution validation**: After transactions execute, `ValidateConsensusAfterExecution` retrieves the modified state and attempts to recover the header round (which contains the old pubkey). [6](#0-5) 

4. **Exception before detection**: The `KeyNotFoundException` is thrown at line 91 during `RecoverFromUpdateValue`, before the replacement detection logic at lines 99-124 can execute. [7](#0-6) 

The replacement detection logic exists but is unreachable because the exception occurs first. The codebase demonstrates the correct pattern in other methods that perform similar operations with proper `ContainsKey` checks. [8](#0-7) 

## Impact Explanation

**Consensus Availability Impact:**
- Blocks containing miner replacement transactions with UpdateValue behavior fail validation with an unhandled exception
- Block validation failure prevents block acceptance by the network
- Affects consensus reliability and chain availability
- The failure occurs after transaction execution, potentially leaving state in an inconsistent condition between the executing node and validating nodes

**Affected Operations:**
- Any legitimate miner replacement operation during UpdateValue blocks
- Normal consensus operations if replacement transactions are broadcast during active mining periods
- Network validators that attempt to validate affected blocks

**Severity Justification:** Medium-High. While not directly causing fund loss, this vulnerability:
- Disrupts core consensus operations
- Can cause legitimate blocks to be rejected
- Affects network availability
- Can be triggered during normal operational procedures (miner key rotation)

## Likelihood Explanation

**Access Control Requirements:**
The vulnerability requires being the admin of a currently active miner's pubkey. [9](#0-8) 

**Triggering Conditions:**
1. Actor must be (or control) the admin of a current miner's candidate pubkey
2. Submit `ReplaceCandidatePubkey` transaction during or just before the target miner's time slot
3. The mining node includes the transaction in their block with UpdateValue behavior
4. Post-execution validation fails with `KeyNotFoundException`

**Feasibility Assessment:**
- **Intentional Attack**: Requires the attacker to be an active miner or control a miner's admin rights (medium barrier)
- **Accidental Trigger**: More likely - legitimate miners performing key rotation could unknowingly trigger this during their mining period
- **No Special Conditions**: Once access is achieved, the vulnerability is reliably triggerable

**Probability:** Medium. The access requirement (active miner admin) is a moderate barrier, but once achieved, the vulnerability is deterministically triggerable. More importantly, this can occur accidentally during legitimate miner key rotation operations.

## Recommendation

Add a `ContainsKey` check inside the foreach loop before accessing the dictionary, consistent with the pattern used elsewhere in the codebase:

```csharp
foreach (var information in providedRound.RealTimeMinersInformation)
{
    if (!RealTimeMinersInformation.ContainsKey(information.Key))
        continue;
        
    RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
        information.Value.SupposedOrderOfNextRound;
    RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
        information.Value.FinalOrderOfNextRound;
    RealTimeMinersInformation[information.Key].PreviousInValue =
        information.Value.PreviousInValue;
}
```

This matches the defensive pattern used in other consensus methods. [10](#0-9) 

## Proof of Concept

A test case would demonstrate:
1. Initialize consensus with multiple miners
2. Call `ReplaceCandidatePubkey` as the admin of an active miner
3. Generate an UpdateValue block that includes this replacement transaction
4. Verify that `ValidateConsensusAfterExecution` throws `KeyNotFoundException` when processing the block header

The test would show that the block header contains the old pubkey in its consensus extra data, but the current state has already been modified to contain the new pubkey, causing the dictionary access to fail during recovery.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-184)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L136-146)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-92)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L99-124)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L25-30)
```csharp
        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L10-10)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return this;
```
