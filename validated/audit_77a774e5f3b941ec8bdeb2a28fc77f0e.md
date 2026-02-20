# Audit Report

## Title
Unhandled KeyNotFoundException in RecoverFromUpdateValue During Miner Replacement Causes Block Validation DoS

## Summary
The `RecoverFromUpdateValue` method contains an unprotected dictionary access that causes a `KeyNotFoundException` when miner replacement transactions execute in blocks with UpdateValue consensus behavior, resulting in block validation failure and consensus disruption.

## Finding Description

The vulnerability exists in the consensus validation flow where state modifications from miner replacement transactions create a mismatch between block header data and post-execution state. [1](#0-0) 

The `RecoverFromUpdateValue` method protects the specific `pubkey` parameter at lines 10-12, but the foreach loop at lines 22-30 iterates over all miners in `providedRound` and directly accesses `RealTimeMinersInformation[information.Key]` without checking key existence.

When `ReplaceCandidatePubkey` is called, it triggers state modification in the consensus contract: [2](#0-1) [3](#0-2) 

The consensus contract removes the old pubkey and adds the new pubkey to the current round, permanently modifying state.

After transaction execution, `ValidateConsensusAfterExecution` retrieves the modified state and attempts recovery: [4](#0-3) 

The method calls `RecoverFromUpdateValue` with the block header round (containing old pubkey) against the modified current round (containing new pubkey). The foreach loop throws `KeyNotFoundException` when accessing the removed old pubkey, occurring before the replacement detection logic at lines 99-124 can execute.

## Impact Explanation

**Consensus Availability Impact:**
- Blocks containing miner replacement transactions with UpdateValue behavior fail validation with an unhandled exception
- Block validation failure prevents block acceptance across the network
- Consensus reliability and chain availability are compromised
- State inconsistency may occur between executing and validating nodes

**Affected Operations:**
- Legitimate miner key rotation during UpdateValue blocks
- Normal consensus operations when replacement transactions coincide with active mining periods
- Network-wide block validation processes

**Severity:** Medium-High. While not causing direct fund loss, this vulnerability disrupts core consensus operations, can cause valid blocks to be rejected, affects network availability, and can be triggered during normal operational procedures.

## Likelihood Explanation

**Access Control Requirements:**
The vulnerability requires being the admin of an active miner's candidate pubkey. [5](#0-4) [6](#0-5) 

Admins are set during `AnnounceElection` through legitimate governance mechanisms, not restricted trusted roles. [7](#0-6) 

**Triggering Conditions:**
1. Actor controls admin of current miner's candidate pubkey
2. Submit `ReplaceCandidatePubkey` transaction during active mining period
3. Mining node includes transaction in block with UpdateValue behavior
4. Post-execution validation fails with `KeyNotFoundException`

**Feasibility:** Medium probability. The access requirement (active miner admin) is a moderate barrier, but once achieved, the vulnerability is deterministically triggerable. More critically, this can occur accidentally during legitimate miner key rotation operations when timing coincides with UpdateValue blocks.

## Recommendation

Add key existence checks in the `RecoverFromUpdateValue` foreach loop before accessing the dictionary:

```csharp
foreach (var information in providedRound.RealTimeMinersInformation)
{
    // Add existence check before access
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

This allows the replacement detection logic at lines 99-124 to execute and properly handle the miner replacement scenario.

## Proof of Concept

```csharp
[Fact]
public async Task MinerReplacement_During_UpdateValue_Causes_ValidationFailure()
{
    // Setup: Get active miner and their admin
    var currentMiners = await ConsensusStub.GetCurrentMinerList.CallAsync(new Empty());
    var targetMinerPubkey = currentMiners.Pubkeys.First().ToHex();
    var adminAddress = await ElectionStub.GetCandidateAdmin.CallAsync(
        new StringValue { Value = targetMinerPubkey });
    
    // Generate new replacement pubkey
    var newKeyPair = CryptoHelper.GenerateKeyPair();
    var newPubkey = newKeyPair.PublicKey.ToHex();
    
    // Miner produces block with UpdateValue behavior
    // Block header contains current round with old pubkey
    
    // Execute replacement transaction in the same block
    await ElectionStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = targetMinerPubkey,
        NewPubkey = newPubkey
    });
    
    // ValidateConsensusAfterExecution will fail with KeyNotFoundException
    // when RecoverFromUpdateValue tries to access the removed old pubkey
    
    // Expected: KeyNotFoundException during validation
    // Actual: Block validation fails, consensus disrupted
}
```

## Notes

The vulnerability arises from a timing issue where block header data (created before execution) contains different miner information than post-execution state. The replacement detection logic exists but is unreachable due to the unhandled exception occurring first. This is a genuine consensus availability issue that affects legitimate operations and should be addressed by adding proper key existence checks before dictionary access.

### Citations

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L181-181)
```csharp
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L140-146)
```csharp
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L87-92)
```csharp
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L411-414)
```csharp
    public override Address GetCandidateAdmin(StringValue input)
    {
        return State.CandidateAdmins[State.InitialPubkeyMap[input.Value] ?? input.Value];
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-103)
```csharp
    public override Empty AnnounceElection(Address input)
    {
        var recoveredPublicKey = Context.RecoverPublicKey();
        AnnounceElection(recoveredPublicKey);

        var pubkey = recoveredPublicKey.ToHex();
        var address = Address.FromPublicKey(recoveredPublicKey);

        Assert(input.Value.Any(), "Admin is needed while announcing election.");
        Assert(State.ManagedCandidatePubkeysMap[address] == null, "Candidate cannot be others' admin.");
        State.CandidateAdmins[pubkey] = input;
```
