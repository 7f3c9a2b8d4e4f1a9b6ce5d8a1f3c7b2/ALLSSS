### Title
Miner Replacement Accepts Historical Candidates Without Current Stake Validation

### Summary
The `GenerateNextRoundInformation()` function replaces evil miners with alternative candidates selected from a historical election snapshot without validating current candidate status, active votes, or stake. This allows former candidates who have quit or whose votes have expired to become miners without any locked capital at risk, violating the security model where miners must have stake.

### Finding Description

The vulnerability exists in the miner replacement flow across two contracts:

**In AEDPoS Contract:**
When generating the next round information, the consensus contract calls the Election contract to get replacement candidates for evil miners. [1](#0-0) 

These alternative candidates are then directly added to the miner list without any validation. [2](#0-1) 

**In Election Contract:**
The `GetMinerReplacementInformation` method selects alternative candidates from a **previous term snapshot** rather than current state. [3](#0-2) 

The snapshot retrieval filters out currently banned candidates but does not validate current candidacy status or active votes. [4](#0-3) 

The snapshot is created at term end and contains historical vote amounts, not current state. [5](#0-4) 

**Why Protections Fail:**
- The only current-state check is whether a pubkey is banned (line 145 in ViewMethods.cs)
- No check for `State.CandidateInformationMap[pubkey].IsCurrentCandidate` 
- No verification of current votes in `State.CandidateVotes`
- Candidates can quit election during the current term, removing themselves from active candidacy while remaining in historical snapshots [6](#0-5) 

### Impact Explanation

**Direct Harm:**
- **Consensus Integrity Breach**: Unauthorized entities without stake become miners and participate in consensus
- **Economic Security Violation**: Miners earn block rewards (calculated per block) without having locked capital at risk [7](#0-6) 
- **No Slashing Mechanism**: If the unauthorized miner misbehaves, there is no stake to slash since they have no locked tokens

**Who Is Affected:**
- All token holders: dilution from unearned mining rewards
- Legitimate miners: reduced rewards due to additional unauthorized participants
- Network security: compromised by miners with no skin in the game

**Severity Justification:**
This is **Critical** because it allows complete bypass of the fundamental security model where miners must lock stake. An attacker can gain mining privileges, extract economic value, and potentially disrupt consensus without any locked capital, deposit, or even active candidate registration.

### Likelihood Explanation

**Attacker Capabilities:**
- Register as candidate in Term N with sufficient votes to rank in top candidates
- Wait for Term N to end (snapshot taken)
- In Term N+1: quit election via `QuitElection()`, recovering deposit
- Wait for evil miner detection during Term N+1

**Attack Complexity:**
- **Low**: Only requires initial candidate registration and sufficient votes (achievable through legitimate voting or vote buying)
- No special permissions or exploits needed
- Standard contract interactions only

**Feasibility Conditions:**
- Terms have defined duration (`State.TimeEachTerm.Value`), making timing predictable
- Evil miner detection occurs naturally in the system when miners miss time slots [8](#0-7) 
- Vote lock periods can expire between terms based on `State.MinimumLockTime` to `State.MaximumLockTime` [9](#0-8) 

**Detection/Operational Constraints:**
- Difficult to detect: the miner appears legitimate in the miner list
- No on-chain signals differentiating legitimate vs unauthorized miners
- Occurs through normal consensus flow without anomalous transactions

**Probability:** HIGH - all preconditions are realistic and achievable within normal system operation.

### Recommendation

**Code-Level Mitigation:**

In `GetMinerReplacementInformation` (Election contract), add validation for each alternative candidate before adding to the list:

```csharp
foreach (var candidateKey in maybeNextCandidates.Select(c => c.Key).Take(take))
{
    // Verify candidate is currently registered and active
    var candidateInfo = State.CandidateInformationMap[candidateKey];
    if (candidateInfo == null || !candidateInfo.IsCurrentCandidate)
        continue;
    
    // Verify candidate has current active votes
    var candidateVotes = State.CandidateVotes[candidateKey];
    if (candidateVotes == null || candidateVotes.ObtainedActiveVotedVotesAmount <= 0)
        continue;
    
    // Verify candidate is in current candidate list
    if (!State.Candidates.Value.Value.Contains(
        ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(candidateKey))))
        continue;
    
    alternativeCandidates.Add(candidateKey);
}
```

**Invariant Checks:**
- Alternative candidates MUST have `IsCurrentCandidate == true`
- Alternative candidates MUST have `ObtainedActiveVotedVotesAmount > 0`
- Alternative candidates MUST exist in `State.Candidates.Value`
- Alternative candidates MUST not be in `State.BannedPubkeyMap`

**Test Cases:**
1. Candidate quits election then evil miner detected → should NOT be selected
2. Candidate's votes all withdrawn then evil miner detected → should NOT be selected
3. Candidate with expired votes → should NOT be selected
4. Verify alternative must be in current candidate list, not just historical snapshot

### Proof of Concept

**Initial State:**
- Term N: Attacker registers as candidate, obtains 1,000,000 votes with 12-month lock
- Term N ends at block height H, snapshot taken with attacker ranked #8 by votes
- Term N+1 begins

**Attack Steps:**

1. **Block H+1000**: Attacker calls `QuitElection(attackerPubkey)`
   - Attacker removed from `State.Candidates.Value`
   - `IsCurrentCandidate` set to false
   - Deposit unlocked and returned
   - Attacker withdraws all votes from Vote contract

2. **Block H+5000**: Legitimate miner M1 misses multiple time slots
   - AEDPoS contract detects evil miner via `TryToDetectEvilMiners()`
   - M1 marked as evil in `UpdateCandidateInformation(IsEvilNode=true)`
   - M1 added to `State.BannedPubkeyMap`

3. **Block H+5001**: Extra block producer generates next round
   - `GenerateNextRoundInformation()` called
   - `GetMinerReplacementInformation()` queries Election contract
   - Returns attacker's pubkey from Term N snapshot (historical data)
   - Attacker has NO current candidate status, NO active votes, NO deposit

4. **Result**: 
   - Attacker added to `currentRound.RealTimeMinersInformation` as miner
   - Attacker can now produce blocks and earn mining rewards
   - Attacker has ZERO locked stake at risk

**Success Condition:** Attacker becomes active miner (`IsCurrentMiner(attackerPubkey) == true`) without being a registered candidate (`State.CandidateInformationMap[attackerPubkey].IsCurrentCandidate == false`) and without active votes (`State.CandidateVotes[attackerPubkey].ObtainedActiveVotedVotesAmount == 0`).

### Notes

The vulnerability stems from using historical election snapshots for real-time security decisions. While snapshots are useful for rewards distribution and historical records, they should not be used to grant active mining privileges without current-state validation. The Election contract's `GetPreviousTermSnapshotWithNewestPubkey()` does filter currently banned candidates, but this is insufficient - it must also validate current candidacy status and active voting stake.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-306)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L311-339)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L393-405)
```csharp
    public override Int64Value GetCurrentTermMiningReward(Empty input)
    {
        if (TryToGetCurrentRoundInformation(out var currentRound))
            return new Int64Value
                { Value = currentRound.GetMinedBlocks().Mul(GetMiningRewardPerBlock()) };

        return new Int64Value { Value = 0 };
    }

    public override Int64Value GetCurrentMiningRewardPerBlock(Empty input)
    {
        return new Int64Value { Value = GetMiningRewardPerBlock() };
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L130-161)
```csharp
    private TermSnapshot GetPreviousTermSnapshotWithNewestPubkey()
    {
        var termNumber = State.CurrentTermNumber.Value.Sub(1);
        var snapshot = State.Snapshots[termNumber];
        if (snapshot == null) return null;
        var invalidCandidates = snapshot.ElectionResult.Where(r => r.Value <= 0).Select(r => r.Key).ToList();
        Context.LogDebug(() => $"Invalid candidates count: {invalidCandidates.Count}");
        foreach (var invalidCandidate in invalidCandidates)
        {
            Context.LogDebug(() => $"Invalid candidate detected: {invalidCandidate}");
            if (snapshot.ElectionResult.ContainsKey(invalidCandidate)) snapshot.ElectionResult.Remove(invalidCandidate);
        }

        if (!snapshot.ElectionResult.Any()) return snapshot;

        var bannedCandidates = snapshot.ElectionResult.Keys.Where(IsPubkeyBanned).ToList();
        Context.LogDebug(() => $"Banned candidates count: {bannedCandidates.Count}");
        if (!bannedCandidates.Any()) return snapshot;
        Context.LogDebug(() => "Getting snapshot and there's miner replaced during current term.");
        foreach (var bannedCandidate in bannedCandidates)
        {
            var newestPubkey = GetNewestPubkey(bannedCandidate);
            // If newest pubkey not exists or same as old pubkey (which is banned), skip.
            if (newestPubkey == null || newestPubkey == bannedCandidate ||
                snapshot.ElectionResult.ContainsKey(newestPubkey)) continue;
            var electionResult = snapshot.ElectionResult[bannedCandidate];
            snapshot.ElectionResult.Add(newestPubkey, electionResult);
            if (snapshot.ElectionResult.ContainsKey(bannedCandidate)) snapshot.ElectionResult.Remove(bannedCandidate);
        }

        return snapshot;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L357-380)
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
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L28-29)
```csharp
        State.MinimumLockTime.Value = input.MinimumLockTime;
        State.MaximumLockTime.Value = input.MaximumLockTime;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L459-479)
```csharp
    private void SavePreviousTermInformation(TakeElectionSnapshotInput input)
    {
        var snapshot = new TermSnapshot
        {
            MinedBlocks = input.MinedBlocks,
            EndRoundNumber = input.RoundNumber
        };

        if (State.Candidates.Value == null) return;

        foreach (var pubkey in State.Candidates.Value.Value)
        {
            var votes = State.CandidateVotes[pubkey.ToHex()];
            var validObtainedVotesAmount = 0L;
            if (votes != null) validObtainedVotesAmount = votes.ObtainedActiveVotedVotesAmount;

            snapshot.ElectionResult.Add(pubkey.ToHex(), validObtainedVotesAmount);
        }

        State.Snapshots[input.TermNumber] = snapshot;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-254)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
        var candidateInformation = State.CandidateInformationMap[pubkey];

        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });

        // Update candidate information.
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
        State.CandidateInformationMap[pubkey] = candidateInformation;
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
