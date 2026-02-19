### Title
Authorization Bypass in Parliament ApproveMultiProposals During Miner List Transition

### Summary
A removed miner can bypass the `AssertCurrentMiner` authorization check in `ApproveMultiProposals` during a miner list transition window. When a miner who was the previous round's extra block producer is removed from the miner list, they retain mining authority until the new round's scheduled start time, allowing them to approve Parliament proposals despite no longer being a legitimate current miner.

### Finding Description

The vulnerability exists in the interaction between Parliament's authorization check and the Consensus contract's miner validation logic during round transitions.

**Entry Point:**
The `ApproveMultiProposals` function performs authorization using `AssertCurrentMiner()` at line 190. [1](#0-0) 

**Authorization Check:**
The `AssertCurrentMiner` method calls the Consensus contract's `IsCurrentMiner` to verify the sender. [2](#0-1) 

**Root Cause - Insufficient Membership Check:**
In the `IsCurrentMiner` implementation, when `IsMinerListJustChanged` is true (indicating a miner list transition), the check to verify the pubkey exists in the current round's miner list is **skipped**. [3](#0-2) 

**Bypass via ExtraBlockProducerOfPreviousRound:**
The function then grants mining authority to the `ExtraBlockProducerOfPreviousRound` if the current time is before the round start time, **without verifying** this pubkey is still in the current miner list. [4](#0-3) 

**Pubkey Resolution from Previous Round:**
The `ConvertAddressToPubkey` method searches for the address in both current AND previous round miner lists, allowing removed miners' addresses to be resolved. [5](#0-4) 

**Miner Replacement Scenario:**
During `GenerateNextRoundInformation`, when miners are replaced due to being identified as evil nodes, the `IsMinerListJustChanged` flag is set to true, and removed miners are excluded from the new round's miner list. [6](#0-5) 

**ExtraBlockProducerOfPreviousRound Assignment:**
When transitioning to the next round, the miner who produces the extra block is recorded as `ExtraBlockProducerOfPreviousRound` in the new round, **even if that miner is subsequently removed** from the new round's miner list. [7](#0-6) 

**IsMinerListJustChanged Flag:**
The flag is set when generating the next round with miner list changes, triggering the vulnerable code path. [8](#0-7) 

**Timing Window:**
The `GetRoundStartTime` returns the expected mining time of the first miner, creating a window between when the new round is committed and when it's scheduled to begin. [9](#0-8) 

### Impact Explanation

**Governance Compromise:**
A removed miner can approve Parliament proposals during the transition window, potentially:
- Approving malicious proposals that change critical system parameters
- Breaking proposal approval thresholds that should have failed
- Manipulating governance decisions after losing legitimate miner status

**Severity Justification:**
- Parliament proposals control critical system configurations, token economics, and cross-chain parameters
- The attacker retains approval authority despite being identified and removed as an evil/malicious miner
- Multiple proposals can be approved in a single transaction via `ApproveMultiProposals`
- This violates the fundamental invariant that only current, legitimate miners should participate in governance

**Affected Parties:**
- All Parliament organizations and their proposals
- System integrity depends on accurate miner authorization
- Other miners and token holders relying on proper governance

### Likelihood Explanation

**Attacker Capabilities:**
The attacker must:
1. Be a current miner who produces the extra block ending a round
2. Be identified for removal (as evil miner) during the subsequent round transition
3. Submit a transaction during the timing window between round commitment and round start time

**Attack Complexity:**
- **Moderate**: Requires being the extra block producer before removal
- The timing window is deterministic and predictable (based on expected mining times)
- The removed miner knows exactly when they've been removed and can prepare the transaction
- Window duration: typically several seconds (the time until first miner's scheduled slot)

**Feasibility Conditions:**
- Miner replacement mechanisms exist and are actively used in AEDPoS
- The `IsMinerListJustChanged` flag is set during these replacements
- The timing window is guaranteed to exist due to how rounds are scheduled
- No additional authentication or verification prevents the removed miner's transaction

**Detection Constraints:**
- The authorization check passes legitimately from the contract's perspective
- No events or logs specifically flag this as abnormal behavior
- Transaction appears valid until deeper analysis reveals the miner was removed

**Probability Assessment:**
- **High**: Once a miner is scheduled for removal, they have knowledge and opportunity
- The precondition (being extra block producer before removal) occurs regularly in rotation
- Economic incentive exists if the miner can manipulate valuable governance decisions
- No technical barriers prevent exploitation once the conditions are met

### Recommendation

**Immediate Fix:**
Modify the `IsCurrentMiner` function to always verify the pubkey exists in the current round's miner list, even when `IsMinerListJustChanged` is true. The check at line 150-155 should be revised to:

```csharp
// Check confirmed extra block producer of previous round.
if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
    currentRound.ExtraBlockProducerOfPreviousRound == pubkey &&
    currentRound.RealTimeMinersInformation.ContainsKey(pubkey)) // ADD THIS CHECK
{
    Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
    return true;
}
```

**Invariant Enforcement:**
Add explicit validation in `GenerateNextRoundInformation` to clear `ExtraBlockProducerOfPreviousRound` if that miner was removed from the current round:

```csharp
if (isMinerListChanged && 
    nextRound.ExtraBlockProducerOfPreviousRound != null &&
    !nextRound.RealTimeMinersInformation.ContainsKey(nextRound.ExtraBlockProducerOfPreviousRound))
{
    nextRound.ExtraBlockProducerOfPreviousRound = null;
}
```

**Test Cases:**
1. Test that a removed miner cannot call `ApproveMultiProposals` after being removed, even if they were the previous extra block producer
2. Test that `IsCurrentMiner` returns false for removed miners during the transition window
3. Test legitimate miners can still produce tiny blocks as extra block producers when appropriate
4. Verify no regression in normal round transition flows

### Proof of Concept

**Initial State:**
- 7 current miners in round N
- Miner A is designated as the extra block producer for round N
- Miner A has missed multiple time slots and will be identified as evil
- Parliament proposal P exists and needs approval

**Exploitation Steps:**

1. **Round N Completion**: Miner A produces the extra block to end round N
   - Miner A's pubkey is recorded in the block's consensus data

2. **Round N+1 Generation**: The extra block triggers round transition
   - `GenerateNextRoundInformation` is called
   - Election contract identifies Miner A as evil (exceeded missed time slots threshold)
   - Miner A is replaced with Alternative Candidate B
   - New round N+1 state: 
     - `IsMinerListJustChanged = true`
     - `ExtraBlockProducerOfPreviousRound = Miner A's pubkey`
     - `RealTimeMinersInformation` contains 7 miners, Miner B replaces Miner A
   - Round N+1 is committed with start time T+10 seconds

3. **Exploit Window**: Current block time is T+2 (before round start time)
   - Miner A submits transaction: `ApproveMultiProposals([P])`

4. **Authorization Bypass**:
   - `AssertCurrentMiner()` calls `IsCurrentMiner(Miner A's address)`
   - `ConvertAddressToPubkey` finds Miner A's pubkey in previous round N
   - `IsCurrentMiner(pubkey)` executes with Miner A's pubkey
   - Line 142-144 check is SKIPPED (IsMinerListJustChanged == true)
   - Line 150-155 check PASSES:
     - Current time (T+2) <= Round start time (T+10) ✓
     - ExtraBlockProducerOfPreviousRound == Miner A's pubkey ✓
   - Returns true, authorization succeeds

5. **Malicious Approval**: Proposal P is approved by the removed miner

**Expected Result**: Transaction should fail with "No permission" error

**Actual Result**: Transaction succeeds, proposal P gains an approval from a non-current miner

**Success Condition**: Removed Miner A successfully approves Parliament proposals despite being excluded from the current miner list, violating the authorization invariant.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L188-201)
```csharp
    public override Empty ApproveMultiProposals(ProposalIdList input)
    {
        AssertCurrentMiner();
        foreach (var proposalId in input.ProposalIds)
        {
            var proposal = State.Proposals[proposalId];
            if (proposal == null || !CheckProposalNotExpired(proposal))
                continue;
            Approve(proposalId);
            Context.LogDebug(() => $"Proposal {proposalId} approved by {Context.Sender}");
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L212-218)
```csharp
    private void AssertCurrentMiner()
    {
        RequireConsensusContractStateSet();
        var isCurrentMiner = State.ConsensusContract.IsCurrentMiner.Call(Context.Sender).Value;
        Context.LogDebug(() => $"Sender is currentMiner : {isCurrentMiner}.");
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L125-134)
```csharp
    private string ConvertAddressToPubkey(Address address)
    {
        if (!TryToGetCurrentRoundInformation(out var currentRound)) return null;
        var possibleKeys = currentRound.RealTimeMinersInformation.Keys.ToList();
        if (TryToGetPreviousRoundInformation(out var previousRound))
            possibleKeys.AddRange(previousRound.RealTimeMinersInformation.Keys);

        return possibleKeys.FirstOrDefault(k =>
            Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(k)) == address);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L136-144)
```csharp
    private bool IsCurrentMiner(string pubkey)
    {
        if (pubkey == null) return false;

        if (!TryToGetCurrentRoundInformation(out var currentRound)) return false;

        if (!currentRound.IsMinerListJustChanged)
            if (!currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
                return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L297-346)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-187)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-14)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L105-108)
```csharp
    public Timestamp GetRoundStartTime()
    {
        return FirstMiner().ExpectedMiningTime;
    }
```
