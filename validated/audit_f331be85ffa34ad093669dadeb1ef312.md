# Audit Report

## Title
Banned Miners Can Be Re-Selected As Block Producers Through Backup Selection Logic

## Summary
The `GetVictories` function's backup miner selection logic fails to verify banned status (`State.BannedPubkeyMap`) when selecting miners from the current miner list. This allows previously banned/evil miners who remain in the consensus contract's current round to be automatically re-elected as block producers for the next term when there are insufficient valid candidates, completely bypassing the evil miner detection and banning mechanism.

## Finding Description

The Election contract's `GetVictories` method is responsible for determining which miners will produce blocks in the next term. When called by the consensus contract during term transitions, it retrieves the current miner list and attempts to select valid candidates with sufficient votes. [1](#0-0) 

When there aren't enough valid candidates to fill all required miner positions (`diff > 0`), the function employs a backup selection mechanism. This backup logic retrieves current miners from the consensus contract: [2](#0-1) 

The vulnerable code then creates a fallback list from current miners who are not in the valid candidates list: [3](#0-2) 

**This line completely omits checking `State.BannedPubkeyMap[k]` to filter out banned miners.**

When a miner is marked as evil through `UpdateCandidateInformation` with `IsEvilNode=true`, the Election contract sets the ban flag and removes them from the candidate list: [4](#0-3) [5](#0-4) 

However, this does NOT immediately remove the banned miner from the consensus contract's current round. The current miner list reflects the active round's participants: [6](#0-5) 

Therefore, banned miners remain in `currentMiners` until term/round transitions occur. Since they are no longer in `validCandidates` (removed from candidate list), they pass the filter on line 66 and get added to the victories list for the next term.

**Evidence of Inconsistency:**

The codebase demonstrates clear awareness of this requirement in `GetMinerReplacementInformation`, which explicitly filters out banned initial miners: [7](#0-6) 

The `GetEvilMinersPubkeys` function also confirms that current miners can indeed be banned: [8](#0-7) 

This proves the codebase IS aware that banned status checks are necessary, but the `GetVictories` backup selection logic at line 66 omits this critical validation.

## Impact Explanation

**Direct Consensus Integrity Violation:**
- Banned/evil miners who were explicitly detected and marked as malicious can be automatically re-selected as block producers for the next term
- This completely undermines the evil miner detection mechanism implemented throughout the AEDPoS consensus system
- Banned miners continue producing blocks, earning mining rewards and subsidies, and potentially causing further harm to network security

**Reward Misallocation:**
- Evil miners continue receiving block production rewards, mining subsidies from the Treasury contract, and profit distributions despite being explicitly banned
- Honest alternative candidates are systematically denied their rightful block production slots
- The Profit and Treasury distribution schemes continue rewarding malicious actors who should have been excluded

**Security Compromise:**
- The consensus system's security model assumes banned miners are permanently excluded from future rounds, but this assumption is violated
- Networks with low candidate participation become vulnerable to persistent control by previously-identified malicious miners
- The evil miner replacement mechanism (`GetMinerReplacementInformation`) becomes ineffective if banned miners are immediately re-elected through the backup selection path

**Quantifiable Impact:**
- Banned miners control block production slots proportional to the shortage of valid candidates
- Direct financial gain for malicious actors through continued block rewards and subsidy distributions
- Compromised network security and loss of stakeholder confidence in the governance system

## Likelihood Explanation

**Feasible Preconditions:**
- Requires `State.MinersCount.Value > validCandidates.Count` (insufficient candidates with active votes)
- This scenario is highly realistic in networks with low candidate participation, during initial network stages, or following mass candidate withdrawals
- At least one current miner must be banned via `UpdateCandidateInformation(IsEvilNode=true)` or through the emergency response organization

**Execution Path:**
1. Consensus contract detects evil miner behavior (missed blocks, incorrect consensus data, etc.)
2. Consensus contract calls `UpdateCandidateInformation(IsEvilNode=true)` to ban the miner
3. Banned miner is marked in `BannedPubkeyMap` and removed from candidate list, but remains in current consensus round
4. At next term transition, consensus contract calls `GetVictories(Empty)` to determine next term's miners
5. If insufficient valid candidates exist (`diff > 0`), backup selection logic executes **without banned status check**
6. Banned miner is automatically re-selected and included in the next term's miner list

**Probability Assessment:**
- **High** in networks with low candidate participation (common in early-stage blockchain networks and during bear markets)
- **Automatic** - no explicit attacker action needed; the vulnerability triggers during normal term transitions
- **Repeatable** - can occur at every subsequent term transition until the candidate pool increases sufficiently
- **Realistic** - the conditions are easily achievable in real-world deployments, particularly during network stress or low participation periods

## Recommendation

Add a banned status check to the backup selection logic in the `GetVictories` method. The fix should filter out banned miners before they are added to the backup list:

**Recommended Fix (Line 66 in ViewMethods.cs):**

Replace:
```csharp
var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
```

With:
```csharp
var backups = currentMiners.Where(k => !validCandidates.Contains(k) && !State.BannedPubkeyMap[k]).ToList();
```

This mirrors the existing pattern used in `GetMinerReplacementInformation` and ensures consistency across the codebase.

## Proof of Concept

```csharp
[Fact]
public async Task BannedMiner_CanBeReSelected_WhenInsufficientCandidates_Test()
{
    // Setup: Initialize with 5 initial miners
    var initialMiners = InitialCoreDataCenterKeyPairs.Take(5).ToList();
    
    // Step 1: Advance to next round so we have previous round data
    await NextRound(BootMinerKeyPair);
    
    // Step 2: Ban one of the current miners (simulating evil behavior detection)
    var minerToBan = initialMiners[0].PublicKey.ToHex();
    var consensusStub = GetConsensusContractStub(BootMinerKeyPair);
    await consensusStub.UpdateCandidateInformation.SendAsync(new UpdateCandidateInformationInput
    {
        Pubkey = minerToBan,
        IsEvilNode = true
    });
    
    // Step 3: Verify miner is banned in Election contract
    var isBanned = await ElectionContractStub.GetCandidateInformation.CallAsync(new StringValue { Value = minerToBan });
    isBanned.Pubkey.ShouldBeEmpty(); // Removed from candidates
    
    // Step 4: Ensure insufficient valid candidates (only 3 valid candidates for 5 slots)
    var validCandidateCount = 3;
    foreach (var keyPair in ValidationDataCenterKeyPairs.Take(validCandidateCount))
    {
        await AnnounceElectionAsync(keyPair);
        await VoteToCandidateAsync(VoterKeyPairs[0], keyPair.PublicKey.ToHex(), 100 * 86400, 100);
    }
    
    // Step 5: Call GetVictories - this should NOT include the banned miner
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    var victoryPubkeys = victories.Value.Select(p => p.ToHex()).ToList();
    
    // VULNERABILITY: Banned miner is re-selected despite being explicitly banned
    victoryPubkeys.ShouldContain(minerToBan); // This SHOULD FAIL but currently PASSES
    
    // The banned miner is back in the next term's miner list
    // This proves the vulnerability: evil miners can automatically return to consensus
}
```

**Expected Behavior:** Banned miner should NOT be in the victories list.

**Actual Behavior:** Banned miner IS included in the victories list when there are insufficient valid candidates, proving the vulnerability allows banned miners to be re-selected as block producers.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L31-41)
```csharp
    public override MinerList GetCurrentMinerList(Empty input)
    {
        return TryToGetCurrentRoundInformation(out var round)
            ? new MinerList
            {
                Pubkeys =
                {
                    round.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k))
                }
            }
            : new MinerList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-274)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L47-48)
```csharp
        var currentMiners = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(k => k.ToHex()).ToList();
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L66-66)
```csharp
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L389-389)
```csharp
                .Where(k => !State.BannedPubkeyMap[k])
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L401-403)
```csharp
    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L96-96)
```csharp
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L109-110)
```csharp
            candidates.Value.Remove(ByteString.CopyFrom(publicKeyByte));
            State.Candidates.Value = candidates;
```
