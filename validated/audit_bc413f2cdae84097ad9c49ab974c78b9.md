# Audit Report

## Title
Evil Miners Continue Block Production After Being Banned Until Next Round Transition

## Summary
When a miner is marked as evil through `UpdateCandidateInformation()` or `RemoveEvilNode()`, the Election contract sets `BannedPubkeyMap` to true, but the Consensus contract does not immediately enforce this ban. Evil miners remain in the current round's `RealTimeMinersInformation` and can continue producing blocks until the next round transition, creating a vulnerability window where officially banned miners participate in consensus.

## Finding Description
When an evil node is detected (either automatically or via governance), the Election contract's `UpdateCandidateInformation()` method is invoked with `IsEvilNode=true`, which sets `State.BannedPubkeyMap[input.Pubkey] = true` in the Election contract's state. [1](#0-0) 

The governance path via `RemoveEvilNode()` allows the emergency response organization to ban miners at any point during a round by calling `UpdateCandidateInformation` with `IsEvilNode=true`. [2](#0-1) 

However, the Consensus contract's permission checks do not consult the banned status. The `PreCheck()` method only verifies miner list membership using `IsInMinerList()` against the current or previous round. [3](#0-2) 

The `IsInMinerList()` method performs no banned status check, only checking if the pubkey exists in `RealTimeMinersInformation.Keys`. [4](#0-3) 

The `MiningPermissionValidationProvider` similarly only validates that the sender's pubkey exists in `BaseRound.RealTimeMinersInformation.Keys` without checking banned status. [5](#0-4) 

Evil miner replacement only occurs during `GenerateNextRoundInformation()`, which is called when preparing the next round's consensus data via `GetConsensusExtraDataForNextRound()`. [6](#0-5) 

The Election contract's `GetMinerReplacementInformation()` is invoked during next round generation and calls `GetEvilMinersPubkeys()` to identify banned miners by checking `State.BannedPubkeyMap[p]`. [7](#0-6) 

This check only happens during next round generation, not during the current round's block production validation.

## Impact Explanation
This breaks the critical consensus security invariant that only authorized, non-malicious miners should participate in block production. When the emergency response organization takes action to ban a miner, the expectation is immediate enforcement, yet the banned miner continues operating.

**Consensus Integrity Violation**: Evil miners marked as banned continue earning mining rewards and producing blocks, undermining the AEDPoS security model.

**Vulnerability Window Duration**: With typical configuration of 17 miners and 4-second intervals, a round spans approximately 68 seconds. If a miner is banned early in their round participation, they could produce multiple additional blocks before round transition.

**Attack Opportunities**: During this window, the evil miner can censor transactions, include malicious transactions, continue earning undeserved rewards, and coordinate with other compromised nodes while officially banned.

The automatic detection threshold is 4320 missed time slots (60 * 24 * 3 = 3 days). [8](#0-7) 

## Likelihood Explanation
**Trigger Path 1 (Lower Risk)**: Automatic detection during `ProcessNextRound()` identifies miners who missed too many time slots via `TryToDetectEvilMiners()` and marks them as evil. [9](#0-8) [10](#0-9)  Since this occurs during round transition, the vulnerability window is minimal.

**Trigger Path 2 (Higher Risk)**: Governance action via `RemoveEvilNode()` can occur at any point during a round, creating a significant vulnerability window. This requires emergency response organization approval but represents a realistic scenario where swift action is needed against a malicious miner.

The vulnerability automatically manifests once either trigger occurs - no additional attacker capabilities are required beyond being the banned miner with remaining time slots in the current round.

## Recommendation
Modify the consensus validation logic to check the banned status in real-time during block production validation. The fix should be implemented in the validation providers:

1. **Option A - Cross-contract call in validation**: Modify `MiningPermissionValidationProvider.ValidateHeaderInformation()` to call the Election contract's ban check before validating miner list membership.

2. **Option B - Synchronous ban enforcement**: When `UpdateCandidateInformation()` is called with `IsEvilNode=true`, immediately remove the banned miner from the current round's `RealTimeMinersInformation` in the Consensus contract via a cross-contract call.

3. **Option C - Cached ban list**: Maintain a synchronized copy of `BannedPubkeyMap` in the Consensus contract state that is checked during validation.

The recommended approach is **Option B** as it provides immediate enforcement without adding cross-contract calls to the hot validation path. Modify `UpdateCandidateInformation()` to notify the Consensus contract to immediately remove the evil miner from the current round.

## Proof of Concept
The vulnerability can be demonstrated by:

1. Having 17 miners in a round with 4-second time slots
2. Emergency response organization calls `RemoveEvilNode()` for a specific miner's pubkey early in the round (e.g., after 10 seconds)
3. The `BannedPubkeyMap[pubkey]` is set to `true` in the Election contract
4. The banned miner's pubkey remains in `currentRound.RealTimeMinersInformation`
5. When the banned miner's time slot arrives, `MiningPermissionValidationProvider` validates their block because it only checks `RealTimeMinersInformation.Keys.Contains(pubkey)`
6. The banned miner successfully produces blocks for the remaining ~58 seconds of the round
7. Only when the next round is generated via `GenerateNextRoundInformation()` does `GetMinerReplacementInformation()` identify the evil miner and replace them

This demonstrates a ~58 second window where a governance-banned miner continues participating in consensus.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-350)
```csharp
    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L285-347)
```csharp
    private void GenerateNextRoundInformation(Round currentRound, Timestamp currentBlockTime, out Round nextRound)
    {
        TryToGetPreviousRoundInformation(out var previousRound);
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();
        var isMinerListChanged = false;
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
        }

        currentRound.GenerateNextRoundInformation(currentBlockTime, blockchainStartTimestamp, out nextRound,
            isMinerListChanged);
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L357-404)
```csharp
    public override MinerReplacementInformation GetMinerReplacementInformation(
        GetMinerReplacementInformationInput input)
    {
        var evilMinersPubKeys = GetEvilMinersPubkeys(input.CurrentMinerList);
        Context.LogDebug(() => $"Got {evilMinersPubKeys.Count} evil miners pubkeys from {input.CurrentMinerList}");
        var alternativeCandidates = new List<string>();
        var latestSnapshot = GetPreviousTermSnapshotWithNewestPubkey();
        // Check out election snapshot.
        if (latestSnapshot != null && latestSnapshot.ElectionResult.Any())
        {
            Context.LogDebug(() => $"Previous term snapshot:\n{latestSnapshot}");
            var maybeNextCandidates = latestSnapshot.ElectionResult
                // Except initial miners.
                .Where(cs =>
                    !State.InitialMiners.Value.Value.Contains(
                        ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
                // Except current miners.
                .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
                .OrderByDescending(s => s.Value).ToList();
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
            Context.LogDebug(() =>
                $"Found alternative miner from candidate list: {alternativeCandidates.Aggregate("\n", (key1, key2) => key1 + "\n" + key2)}");
        }

        // If the count of evil miners is greater than alternative candidates, add some initial miners to alternative candidates.
        var diff = evilMinersPubKeys.Count - alternativeCandidates.Count;
        if (diff > 0)
        {
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
        }

        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
    }

    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```
