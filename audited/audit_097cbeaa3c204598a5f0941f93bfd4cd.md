### Title
Evil Miners Continue Block Production After Being Banned Until Next Round Transition

### Summary
When `UpdateCandidateInformation()` marks a node as evil and removes it from the Election contract's Candidates list, the consensus contract does not immediately remove the node from the active miner list. Evil miners remain in the current round's `RealTimeMinersInformation` and can continue producing blocks until the next round transition occurs, creating a vulnerability window that can span multiple blocks.

### Finding Description

When an evil node is detected through automatic detection or governance action (`RemoveEvilNode`), the `UpdateCandidateInformation()` function is called with `IsEvilNode=true`. This function marks the pubkey as banned and removes it from the Election contract's state: [1](#0-0) 

The function sets `State.BannedPubkeyMap[input.Pubkey] = true`, removes the candidate from `State.Candidates`, and removes their candidate information. However, this does NOT immediately affect the consensus contract's current round state.

The consensus contract's `PreCheck()` method only verifies that a miner is in the current or previous round's miner list, without checking if they are banned: [2](#0-1) 

The `IsInMinerList()` method only checks membership in `RealTimeMinersInformation`, not banned status: [3](#0-2) 

Evil miner replacement only occurs during round transitions when `GenerateNextRoundInformation()` is called, which then invokes `GetMinerReplacementInformation()` to detect and replace banned miners: [4](#0-3) 

The Election contract's `GetEvilMinersPubkeys()` checks the `BannedPubkeyMap`: [5](#0-4) 

However, this check only happens during the generation of the next round via `GetConsensusExtraDataForNextRound()`: [6](#0-5) 

### Impact Explanation

**Consensus Integrity Violation**: Evil miners continue participating in consensus after being identified and banned, undermining the security guarantees of the AEDPoS consensus mechanism. This violates the critical invariant that "miner schedule integrity" must be maintained at all times.

**Time Window**: The vulnerability window extends from when `UpdateCandidateInformation(IsEvilNode=true)` is called until the next round transition. Since AElf rounds contain multiple time slots (one per active miner) and can last for extended periods, this window can be significant.

**Reward Misallocation**: The evil miner continues earning mining rewards during this window, receiving block production rewards they should not be entitled to after being marked as malicious.

**Attack Opportunities**: During this window, the evil miner can:
- Continue producing blocks and potentially include malicious transactions
- Perform censorship by excluding certain transactions
- Coordinate with other compromised nodes for double-spend attempts
- Undermine network security while officially banned

**Affected Parties**: All network participants are affected as consensus security is compromised during the vulnerability window.

### Likelihood Explanation

**Reachable Entry Point**: The vulnerability can be triggered through two realistic paths:
1. Automatic detection via `ProcessNextRound()` when evil miners exceed the missed time slot threshold
2. Governance action via `RemoveEvilNode()` by the emergency response organization [7](#0-6) 

**Feasible Preconditions**: 
- A node is currently an active miner (in the current round's miner list)
- The node is detected as evil or reported through governance
- The consensus contract calls `UpdateCandidateInformation` with `IsEvilNode=true`

**Execution Practicality**: The exploit occurs automatically once the conditions are met. No special attacker capabilities are required beyond being a current miner who gets detected as evil. The evil miner simply continues operating normally until the round ends.

**Attack Complexity**: Low - the vulnerability is inherent in the design. Once marked as evil, the miner automatically continues producing blocks until the next round transition without any additional action required.

**Detection**: While the evil behavior that triggered the banning may be detected, the continued block production during the vulnerability window appears legitimate from a consensus perspective since the miner remains in `RealTimeMinersInformation`.

### Recommendation

**Immediate Fix**: Add a real-time banned status check in the consensus contract's `PreCheck()` method:

```csharp
private bool PreCheck()
{
    TryToGetCurrentRoundInformation(out var currentRound);
    TryToGetPreviousRoundInformation(out var previousRound);

    _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

    // Existing miner list check
    if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
        !previousRound.IsInMinerList(_processingBlockMinerPubkey))
        return false;

    // NEW: Check if miner is banned in Election contract
    if (State.ElectionContract.Value != null)
    {
        var isBanned = State.ElectionContract.IsPubkeyBanned.Call(
            new StringValue { Value = _processingBlockMinerPubkey });
        if (isBanned.Value)
            return false;
    }

    return true;
}
```

**Alternative Fix**: Modify `UpdateCandidateInformation()` to immediately trigger a mid-round miner replacement by calling back to the consensus contract to update the current round's miner list when `IsEvilNode=true`.

**Invariant Check**: Add an assertion that no banned miners exist in the active round's miner list after any `UpdateCandidateInformation` call with `IsEvilNode=true`.

**Test Cases**: 
1. Mark an active miner as evil mid-round and verify they cannot produce the next block
2. Verify banned miners are rejected even if they're in `RealTimeMinersInformation`
3. Test the emergency response organization can immediately remove evil miners from consensus

### Proof of Concept

**Initial State**:
- Miner M is in the current round's active miner list (`RealTimeMinersInformation`)
- Miner M has a scheduled time slot at block height H+10
- Current block height is H

**Attack Steps**:
1. At block H+1, governance calls `RemoveEvilNode(M.pubkey)` through emergency response organization
2. `UpdateCandidateInformation(Pubkey=M, IsEvilNode=true)` is executed:
   - `State.BannedPubkeyMap[M.pubkey] = true`
   - M removed from `State.Candidates`
   - M removed from `State.CandidateInformationMap`
3. At block H+10, M's scheduled time slot arrives
4. M produces a block for height H+10
5. Consensus contract's `PreCheck()` validates M:
   - `currentRound.IsInMinerList(M.pubkey)` returns `true` (M still in `RealTimeMinersInformation`)
   - No banned status check performed
   - Validation passes
6. M's block is accepted and M receives mining rewards
7. M continues producing blocks during subsequent time slots until round transition

**Expected Result**: M should be immediately prevented from producing blocks after being marked as evil.

**Actual Result**: M continues producing blocks and earning rewards until the next round transition, when `GenerateNextRoundInformation()` finally detects M as banned via `GetMinerReplacementInformation()`.

**Success Condition**: An evil miner marked as banned at block H successfully produces one or more blocks at heights > H before the round transitions.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-112)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
            var rankingList = State.DataCentersRankingList.Value;
            if (rankingList.DataCenters.ContainsKey(input.Pubkey))
            {
                rankingList.DataCenters[input.Pubkey] = 0;
                UpdateDataCenterAfterMemberVoteAmountChanged(rankingList, input.Pubkey, true);
                State.DataCentersRankingList.Value = rankingList;
            }

            Context.LogDebug(() => $"Marked {input.Pubkey.Substring(0, 10)} as an evil node.");
            Context.Fire(new EvilMinerDetected { Pubkey = input.Pubkey });
            State.CandidateInformationMap.Remove(input.Pubkey);
            var candidates = State.Candidates.Value;
            candidates.Value.Remove(ByteString.CopyFrom(publicKeyByte));
            State.Candidates.Value = candidates;
            RemoveBeneficiary(input.Pubkey);
            return new Empty();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-351)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L299-342)
```csharp
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
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L401-404)
```csharp
    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-176)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
```
